/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Really basic network simulator, only simulates a simple link using a
 * packet structure. 
 * Init: link creation. Returns a link structure with defined bandwidth,
 * latency, loss pattern and initial time. The link is empty. The loss
 * pattern is a 64 bit bit mask.
 * Submit packet of length L at time t. The packet is queued to the link.
 * Get packet out of link at time T + L + Queue.
 */

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include <stdlib.h>
#include <string.h>

picoquictest_sim_link_t* picoquictest_sim_link_create(double data_rate_in_gps,
    uint64_t microsec_latency, uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t current_time)
{
    picoquictest_sim_link_t* link = (picoquictest_sim_link_t*)malloc(sizeof(picoquictest_sim_link_t));
    if (link != NULL) {
        double pico_d = (data_rate_in_gps <= 0) ? 0 : (8000.0 / data_rate_in_gps);
        memset(link, 0, sizeof(picoquictest_sim_link_t));
        pico_d *= (1.024 * 1.024); /* account for binary units */
        link->next_send_time = current_time;
        link->queue_time = current_time;
        link->queue_delay_max = queue_delay_max;
        link->picosec_per_byte = (uint64_t)pico_d; 
        link->microsec_latency = microsec_latency;
        link->packets_dropped = 0;
        link->packets_sent = 0;
        link->first_packet = NULL;
        link->last_packet = NULL;
        link->loss_mask = loss_mask;
        link->jitter_seed = 0xDEADBEEFBABAC001ull;
        link->jitter = 0;
        link->path_mtu = PICOQUIC_MAX_PACKET_SIZE;
    }

    return link;
}

void picoquictest_sim_link_delete(picoquictest_sim_link_t* link)
{
    picoquictest_sim_packet_t* packet;

    while ((packet = link->first_packet) != NULL) {
        link->first_packet = packet->next_packet;
        free(packet);
    }

    if (link->aqm_state != NULL) {
        link->aqm_state->release(link->aqm_state, link);
    }

    free(link);
}

picoquictest_sim_packet_t* picoquictest_sim_link_create_packet()
{
    picoquictest_sim_packet_t* packet = (picoquictest_sim_packet_t*)malloc(sizeof(picoquictest_sim_packet_t));
    if (packet != NULL) {
        packet->next_packet = NULL;
        packet->arrival_time = 0;
        packet->length = 0;
        packet->ecn_mark = 0;
    }

    return packet;
}

uint64_t picoquictest_sim_link_next_arrival(picoquictest_sim_link_t* link, uint64_t current_time)
{
    picoquictest_sim_packet_t* packet = link->first_packet;

    if (link->aqm_state != NULL) {
        /* Calling the update function to retrieve packets from AQM queue as appropriate */
        link->aqm_state->update(link->aqm_state, link, current_time);
    }

    if (packet != NULL && packet->arrival_time < current_time) {
        current_time = packet->arrival_time;
    }

    return current_time;
}

picoquictest_sim_packet_t* picoquictest_sim_link_dequeue(picoquictest_sim_link_t* link,
    uint64_t current_time)
{
    picoquictest_sim_packet_t* packet = link->first_packet;

    if (packet != NULL && packet->arrival_time <= current_time) {
        link->first_packet = packet->next_packet;
        if (link->first_packet == NULL) {
            link->last_packet = NULL;
        }
    } else {
        packet = NULL;
    }

    return packet;
}

static int picoquictest_sim_link_testloss(uint64_t* loss_mask)
{
    uint64_t loss_bit = 0;

    if (loss_mask != NULL) {
        /* Last bit indicates loss or not */
        loss_bit = (uint64_t)((*loss_mask) & 1ull);

        /* Rotate loss mask by 1 to prepare next round */
        *loss_mask >>= 1;
        *loss_mask |= (loss_bit << 63);
    }

    return (int)loss_bit;
}

static int picoquictest_sim_link_simloss(picoquictest_sim_link_t* link, uint64_t current_time)
{
    int loss = 0;

    if (link->nb_loss_in_burst > 0) {
        if (link->packets_sent > link->packets_sent_next_burst)
        {
            uint64_t picosec_wait = link->nb_loss_in_burst * link->picosec_per_byte * 1536;
            link->packets_sent_next_burst = link->packets_sent + link->packets_between_losses;
            link->nb_losses_this_burst = link->nb_loss_in_burst - 1;
            link->end_of_burst_time = current_time + (picosec_wait / 1000000);
            loss = 1;
        }
        else if (link->nb_losses_this_burst > 0) {
            if (current_time > link->end_of_burst_time) {
                link->nb_losses_this_burst = 0;
            }
            else {
                loss = 1;
                link->nb_losses_this_burst -= 1;
            }
        }
    }
    return loss;
}

/* Jitter can have two modes: wifi or gauss. 
* Gauss variable has a specified mid value and a std deviation
* equal to that value.
* Wifi variable is the sum of three components
* - short term jitter: Poisson of form N1*1000, with lambda=1
* - medium term: X*N2*7000, where:
*     X is 0 if target jitter <= 1000
*     X is 1 if target jitter > 85000
*     otherwise using random r (0..1):
*         X is 0 if r > (jitter - 1000)/84000, 1 otherwise
*         N2 is Poisson with lambda = 12
* This formula is derived empirically from measurements in "bad"
* wifi networks.
 */

uint64_t picoquictest_sim_link_wifi_jitter(picoquictest_sim_link_t* link)
{
    const uint64_t exp_minus_1_x40000000 = 395007542; /* exp(-1) time 2^30 */
    const uint64_t primary_jitter = 1000;
    uint64_t N1 = picoquic_test_poisson_random(&link->jitter_seed, exp_minus_1_x40000000);
    uint64_t jitter = N1 * primary_jitter;
    if (N1 > 0) {
        /* smoothing variable */
        jitter  -= picoquic_test_uniform_random(&link->jitter_seed, primary_jitter);
    }

    if (link->jitter > 1000) {
        uint64_t r = picoquic_test_random(&link->jitter_seed);
        r ^= r >> 30;
        r &= 0x3fffffff;
        r *= 84000;
        if (r < ((link->jitter - 1000) << 30)) {
            const uint64_t exp_minus_12_x40000000 = 6597; /* exp(-12) time 2^30 */
            const uint64_t secondary_jitter = 7500;
            uint64_t N2 = picoquic_test_poisson_random(&link->jitter_seed, exp_minus_12_x40000000);
            jitter += N2 * secondary_jitter;
            if (N2 > 1) {
                jitter -= picoquic_test_uniform_random(&link->jitter_seed, secondary_jitter);
            }
        }
    }
    return jitter;
}

uint64_t picoquictest_sim_link_jitter(picoquictest_sim_link_t* link)
{
    uint64_t jitter;

    if (link->jitter_mode == jitter_wifi) {
        jitter = picoquictest_sim_link_wifi_jitter(link);
    }
    else {
        double x = picoquic_test_gauss_random(&link->jitter_seed);
        jitter = link->jitter;
        if (x < -3.0) {
            x = -3.0;
        }
        x /= 3.0;
        jitter += (int64_t)(x * (double)jitter);
    }
    return jitter;
}

/* picoquictest_sim_link_enqueue:
* submit a packet to the link's "latency queue", bypassing the AQM.
 */

void picoquictest_sim_link_enqueue(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet,
    uint64_t current_time, int should_drop)
{
    if (should_drop) {
        /* simulate congestion loss or random drop on queue full */
        link->packets_dropped++;
        free(packet);
    }
    else {
        uint64_t transmit_time = picoquictest_sim_link_transmit_time(link, packet);

        if (current_time > link->queue_time) {
            link->queue_time = current_time;
        } 
        link->queue_time += transmit_time;

        if (packet->length > link->path_mtu || picoquictest_sim_link_testloss(link->loss_mask) != 0 ||
            link->is_switched_off || picoquictest_sim_link_simloss(link, current_time)) {
            link->packets_dropped++;
            free(packet);
        }
        else {
            link->packets_sent++;
            if (link->last_packet == NULL) {
                link->first_packet = packet;
            }
            else {
                link->last_packet->next_packet = packet;
            }
            link->last_packet = packet;
            packet->next_packet = NULL;
            packet->arrival_time = link->queue_time + link->microsec_latency;
            if (link->jitter != 0) {
                packet->arrival_time += picoquictest_sim_link_jitter(link);
            }
            if (packet->arrival_time < link->resume_time) {
                packet->arrival_time = link->resume_time;
            }
        }
    }
}

uint64_t picoquictest_sim_link_transmit_time(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet)
{
    return ((link->picosec_per_byte * ((uint64_t)packet->length)) >> 20);
}

uint64_t picoquictest_sim_link_queue_delay(picoquictest_sim_link_t* link, uint64_t current_time)
{
    return (current_time > link->queue_time) ? 0 : link->queue_time - current_time;
}

void picoquictest_sim_link_submit(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet,
    uint64_t current_time)
{
    uint64_t queue_delay = picoquictest_sim_link_queue_delay(link, current_time);
    int should_drop = 0;
#if 1
#else
    uint64_t transmit_time = picoquictest_sim_link_transmit_time(link, packet);

    if (transmit_time <= 0)
        transmit_time = 1;
#endif

    if (link->is_suspended) {
        packet->arrival_time = UINT64_MAX;
        if (link->last_packet == NULL) {
            link->first_packet = packet;
        }
        else {
            link->last_packet->next_packet = packet;
        }
        link->last_packet = packet;
        return;
    }
    if (link->aqm_state != NULL) {
        link->aqm_state->submit(link->aqm_state, link, packet, current_time, &should_drop);
    }
    else if (link->queue_delay_max > 0 && queue_delay >= link->queue_delay_max) {
        should_drop = 1;
    }

#if 1
    picoquictest_sim_link_enqueue(link, packet, current_time, should_drop);
#else
    if (!should_drop) {
        link->queue_time = current_time + queue_delay + transmit_time;
        /* TODO: proper simulation of marking policy */
#if 0
        if (link->l4s_max > 0 && queue_delay >= link->l4s_max) {
            packet->ecn_mark = PICOQUIC_ECN_CE;
        }
#endif
        if (packet->length > link->path_mtu || picoquictest_sim_link_testloss(link->loss_mask) != 0 ||
            link->is_switched_off || picoquictest_sim_link_simloss(link, current_time)) {
            link->packets_dropped++;
            free(packet);
        } else {
            link->packets_sent++;
            if (link->last_packet == NULL) {
                link->first_packet = packet;
            } else {
                link->last_packet->next_packet = packet;
            }
            link->last_packet = packet;
            packet->next_packet = NULL;
            packet->arrival_time = link->queue_time + link->microsec_latency;
            if (link->jitter != 0) {
                packet->arrival_time += picoquictest_sim_link_jitter(link);
            }
            if (packet->arrival_time < link->resume_time) {
                packet->arrival_time = link->resume_time;
            }

        }
    } else {
        /* simulate congestion loss or random drop on queue full */
        link->packets_dropped++;
        free(packet);
    }
#endif
}

/*
* Simulate a brief suspension of transmission on a link, similar to what
* happens when a Wi-Fi transmission gets suspended while scanning other
* radio channels. The existing packets are queued for delivery at the end of the interval.
*/

void picoquic_test_simlink_suspend(picoquictest_sim_link_t* link, uint64_t time_end_of_interval, int simulate_receive)
{
    picoquictest_sim_packet_t* packet;
    picoquictest_sim_packet_t* first_old;

    if (simulate_receive) {
        /* specify the resume time */
        link->resume_time = time_end_of_interval;
        /* packets scheduled to arrive before the end of the interval are rescheduled to
         * that end of interval time.
         */
        packet = link->first_packet;
        while (packet != NULL && packet->arrival_time < time_end_of_interval) {
            packet->arrival_time = time_end_of_interval;
            packet = packet->next_packet;
        }
    }
    else {
        /* Reset the queue delay to the end of interval */
        link->queue_time = time_end_of_interval;
        /* stash the old queue, and reset the queue pointers */
        first_old = link->first_packet;
        link->first_packet = NULL;
        link->last_packet = NULL;
        /* resubmit all packets at the end of interval time */
        packet = first_old;
        while (packet != NULL) {
            picoquictest_sim_packet_t* next_packet = packet->next_packet;
            packet->next_packet = NULL;
            picoquictest_sim_link_submit(link, packet, time_end_of_interval);
            packet = next_packet;
        }
    }
}

int sim_link_one_test(uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t nb_losses)
{
    int ret = 0;
    uint64_t current_time = 0;
    uint64_t departure_time = 0;
    picoquictest_sim_link_t* link = picoquictest_sim_link_create(0.01, 10000, loss_mask, queue_delay_max, current_time);
    uint64_t dequeued = 0;
    uint64_t queued = 0;
    const uint64_t nb_packets = 16;

    if (link == NULL) {
        ret = -1;
    }
    else {

        while (ret == 0) {
            if (queued >= nb_packets) {
                departure_time = UINT64_MAX;
            }

            current_time = picoquictest_sim_link_next_arrival(link, departure_time);

            picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, current_time);

            if (packet != NULL) {
                dequeued++;
                free(packet);
            }
            else if (queued < nb_packets) {
                packet = picoquictest_sim_link_create_packet();

                if (packet == NULL) {
                    ret = -1;
                }
                else {
                    packet->length = sizeof(packet->bytes);
                    picoquictest_sim_link_submit(link, packet, departure_time);
                    departure_time += 250;
                    queued++;
                }
            }
            else {
                break;
            }
        }

        if ((dequeued + nb_losses) != nb_packets) {
            ret = -1;
        }
        
        picoquictest_sim_link_delete(link);
    }

    return ret;
}

int sim_link_test()
{
    int ret = 0;
    uint64_t loss_mask = 0;
    
    ret = sim_link_one_test(&loss_mask, 0, 0);

    if (ret == 0) {
        loss_mask = 8;
        ret = sim_link_one_test(&loss_mask, 0, 1);
    }

    if (ret == 0) {
        loss_mask = 0x18;
        ret = sim_link_one_test(&loss_mask, 0, 2);
    }

    return ret;
}

void picoquic_set_test_address(struct sockaddr_in * addr, uint32_t addr_val, uint16_t port)
{
    /* Init of the IP addresses */
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef _WINDOWS
    addr->sin_addr.S_un.S_addr = addr_val;
#else
    addr->sin_addr.s_addr = addr_val;
#endif
    addr->sin_port = port;
}
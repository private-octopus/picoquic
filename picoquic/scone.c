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

#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include <stdlib.h>
#include <string.h>

uint64_t scone_indication[128] = {
    100000ull /* 0 */,
    112202ull /* 1 */,
    125893ull /* 2 */,
    141254ull /* 3 */,
    158489ull /* 4 */,
    177828ull /* 5 */,
    199526ull /* 6 */,
    223872ull /* 7 */,
    251189ull /* 8 */,
    281838ull /* 9 */,
    316228ull /* 10 */,
    354813ull /* 11 */,
    398107ull /* 12 */,
    446684ull /* 13 */,
    501187ull /* 14 */,
    562341ull /* 15 */,
    630957ull /* 16 */,
    707946ull /* 17 */,
    794328ull /* 18 */,
    891251ull /* 19 */,
    1000000ull /* 20 */,
    1122018ull /* 21 */,
    1258925ull /* 22 */,
    1412538ull /* 23 */,
    1584893ull /* 24 */,
    1778279ull /* 25 */,
    1995262ull /* 26 */,
    2238721ull /* 27 */,
    2511886ull /* 28 */,
    2818383ull /* 29 */,
    3162278ull /* 30 */,
    3548134ull /* 31 */,
    3981072ull /* 32 */,
    4466836ull /* 33 */,
    5011872ull /* 34 */,
    5623413ull /* 35 */,
    6309573ull /* 36 */,
    7079458ull /* 37 */,
    7943282ull /* 38 */,
    8912509ull /* 39 */,
    10000000ull /* 40 */,
    11220185ull /* 41 */,
    12589254ull /* 42 */,
    14125375ull /* 43 */,
    15848932ull /* 44 */,
    17782794ull /* 45 */,
    19952623ull /* 46 */,
    22387211ull /* 47 */,
    25118864ull /* 48 */,
    28183829ull /* 49 */,
    31622777ull /* 50 */,
    35481339ull /* 51 */,
    39810717ull /* 52 */,
    44668359ull /* 53 */,
    50118723ull /* 54 */,
    56234133ull /* 55 */,
    63095734ull /* 56 */,
    70794578ull /* 57 */,
    79432823ull /* 58 */,
    89125094ull /* 59 */,
    100000000ull /* 60 */,
    112201845ull /* 61 */,
    125892541ull /* 62 */,
    141253754ull /* 63 */,
    158489319ull /* 64 */,
    177827941ull /* 65 */,
    199526231ull /* 66 */,
    223872114ull /* 67 */,
    251188643ull /* 68 */,
    281838293ull /* 69 */,
    316227766ull /* 70 */,
    354813389ull /* 71 */,
    398107171ull /* 72 */,
    446683592ull /* 73 */,
    501187234ull /* 74 */,
    562341325ull /* 75 */,
    630957344ull /* 76 */,
    707945784ull /* 77 */,
    794328235ull /* 78 */,
    891250938ull /* 79 */,
    1000000000ull /* 80 */,
    1122018454ull /* 81 */,
    1258925412ull /* 82 */,
    1412537545ull /* 83 */,
    1584893192ull /* 84 */,
    1778279410ull /* 85 */,
    1995262315ull /* 86 */,
    2238721139ull /* 87 */,
    2511886432ull /* 88 */,
    2818382931ull /* 89 */,
    3162277660ull /* 90 */,
    3548133892ull /* 91 */,
    3981071706ull /* 92 */,
    4466835922ull /* 93 */,
    5011872336ull /* 94 */,
    5623413252ull /* 95 */,
    6309573445ull /* 96 */,
    7079457844ull /* 97 */,
    7943282347ull /* 98 */,
    8912509381ull /* 99 */,
    10000000000ull /* 100 */,
    11220184543ull /* 101 */,
    12589254118ull /* 102 */,
    14125375446ull /* 103 */,
    15848931925ull /* 104 */,
    17782794100ull /* 105 */,
    19952623150ull /* 106 */,
    22387211386ull /* 107 */,
    25118864315ull /* 108 */,
    28183829313ull /* 109 */,
    31622776602ull /* 110 */,
    35481338923ull /* 111 */,
    39810717055ull /* 112 */,
    44668359215ull /* 113 */,
    50118723363ull /* 114 */,
    56234132519ull /* 115 */,
    63095734448ull /* 116 */,
    70794578438ull /* 117 */,
    79432823472ull /* 118 */,
    89125093813ull /* 119 */,
    100000000000ull /* 120 */,
    112201845430ull /* 121 */,
    125892541179ull /* 122 */,
    141253754462ull /* 123 */,
    158489319246ull /* 124 */,
    177827941004ull /* 125 */,
    199526231497ull /* 126 */,
    0 /* 127 */
};

/*
* TODO: this padding should only happen on the very first packet of a connection.
* Maybe add a test. Also, maybe make sure that the formatting of the first packet
* always leaves 2 empty bits at the end. */
void picoquic_scone_padding(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length)
{
    if (length < 2) {
        if (length > 0) {
            *bytes = 0;
        }
    }
    else if (cnx->client_mode &&
        cnx->cnx_state < picoquic_state_client_handshake_start &&
        cnx->path[0]->nb_retransmit == 0) {
        /* keeping it simple for now */
        memset(bytes, 0, length - 2);
        bytes += length - 2;
        bytes[0] = (SCONE_INDICATOR>>8)&0xff;
        bytes[1] = SCONE_INDICATOR & 0xff;
        if (!cnx->is_scone_indicator_sent) {
            cnx->is_scone_indicator_sent = 1;
            picoquic_log_app_message(cnx, "Scone indicator sent");
        }
    }
    else {
        memset(bytes, 0, length);
    }
}

int picoquic_scone_incoming(picoquic_quic_t* quic, picoquic_packet_header* ph, const uint8_t* bytes_start, const uint8_t * bytes_max)
{
    int ret = -1;
    const uint8_t * bytes = bytes_start + 5;

    /* The SCONE signal is only notified if the next packet has the same CID and is
    * properly decrypted. At this point, we verify that the next packet is a 1RTT
    * packet (short header) and that its first bytes match the destination CID. */
    if (quic->default_tp.is_scone_supported &&
        (ph->vn & 0x7fffffff) == SCONE_VERSION_BASE &&
        (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &ph->dest_cnx_id)) != NULL &&
        (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &ph->srce_cnx_id)) != NULL &&
        ph->dest_cnx_id.id_len == quic->local_cnxid_length &&
        bytes + 1 + ph->dest_cnx_id.id_len < bytes_max &&
        (bytes[0] & 0x80) == 0 &&
        memcmp(bytes + 1, ph->dest_cnx_id.id, ph->dest_cnx_id.id_len) == 0) {
        /* Looks good */
        quic->scone_indication = scone_indication[(((*bytes_start) & 0x3f) << 1) + (ph->vn >> 31)];
        ph->offset = bytes - bytes_start;
        ph->payload_length = 0;
        ret = 0;
    }
    /* TODO: if skip scone if inadequate but not malformed, should we just skip it? */
    return ret;
}

/* Notify the application after the next coalesced packet was received correctly 
* TODO: check that this is a coalesced packet.
*/
void picoquic_scone_report(picoquic_cnx_t * cnx, int path_index)
{
    if (cnx->quic->scone_indication != 0 && path_index >= 0) {
        picoquic_path_t* path_x = cnx->path[path_index];
        if (cnx->callback_fn != NULL){
            (void)cnx->callback_fn(path_x->cnx, cnx->quic->scone_indication, NULL, (size_t)path_x->unique_path_id, picoquic_callback_scone_indication,
                cnx->callback_ctx, NULL);
        }
        path_x->scone_advice_last = path_x->cnx->quic->scone_indication;
        picoquic_log_app_message(cnx, "Scone advice received, %" PRIu64 " bps.", cnx->quic->scone_indication);
        cnx->quic->scone_indication = 0;
    }
}

/* Prepare a scone packet if the time to send it has come. */

uint8_t* picoquic_scone_format_packet(uint8_t* bytes, const uint8_t* bytes_max, unsigned int signal,
    picoquic_connection_id_t* dcid, picoquic_connection_id_t* scid)
{
    if (bytes + 6 < bytes_max) {
        bytes[0] = (uint8_t)(0xC0 + ((signal >> 1) & 0x3f));
        bytes[1] = (uint8_t)((SCONE_VERSION_BASE >> 24) & 0xff) + (((signal & 1) > 0) ? 0x80 : 0);
        bytes[2] = (uint8_t)((SCONE_VERSION_BASE >> 16) & 0xff);
        bytes[3] = (uint8_t)((SCONE_VERSION_BASE >> 8) & 0xff);
        bytes[4] = (uint8_t)(SCONE_VERSION_BASE & 0xff);
        bytes += 5;
        if ((bytes = picoquic_frames_cid_encode(bytes, bytes_max, dcid)) != NULL) {
            bytes = picoquic_frames_cid_encode(bytes, bytes_max, scid);
        }
    }
    else {
        bytes = NULL;
    }
    return bytes;
}

int picoquic_scone_ready_to_send(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    return (cnx->local_parameters.is_scone_supported &&
        cnx->remote_parameters.is_scone_supported &&
        cnx->cnx_state == picoquic_state_ready &&
        current_time >= path_x->scone_next_send_time);
}

int picoquic_scone_prepare(picoquic_cnx_t * cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t * packet_buffer, size_t available, size_t * segment_length, uint64_t * next_wake_time, int * is_initial_sent)
{
    int ret = 0;
    /* This function should only be called after picoquic_scone_ready_to_send returns true, i.e. != 0 */

    uint8_t* bytes = picoquic_scone_format_packet(packet_buffer, packet_buffer + available, 127,
        &path_x->first_tuple->p_remote_cnxid->cnx_id, &path_x->first_tuple->p_local_cnxid->cnx_id);
    if (bytes != NULL) {
        /* format the next segment */
        size_t coalesced_packet_size = bytes - packet_buffer;
        size_t next_segment_length = 0;

        ret = picoquic_prepare_segment(cnx, path_x, packet, current_time,
            bytes, available - coalesced_packet_size, &next_segment_length, next_wake_time, is_initial_sent, 1);
        if (ret == 0 && next_segment_length > 0) {
            /* we are actually sending a segment.
            * add the SCONE packet size to the segment length,
            * and update the scone timer.
            */
            *segment_length = next_segment_length + coalesced_packet_size;

            picoquic_log_app_message(cnx, "Scone advice requested.");
            if (path_x->scone_next_send_time < current_time) {
                path_x->scone_next_send_time = current_time;
            }
            path_x->scone_next_send_time += SCONE_DELAY + picoquic_uniform_random(SCONE_DELAY_RANDOM);
        }
    }
    else {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    return ret;
}

/* TODO:
* write tests.
* use conditional compiling.
*/

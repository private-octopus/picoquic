#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define PICOQUIC_FC_ACTION_JOIN 0x01
#define PICOQUIC_FC_ACTION_LEAVE 0x02
#define PICOQUIC_FC_ACTION_LISTEN 0x03

int picoquic_compare_flow_id(picoquic_fc_flow_id_t *flow_id_1,
                             picoquic_fc_flow_id_t *flow_id_2)
{
    if (flow_id_1->id_len != flow_id_2->id_len)
        return 0;

    for (int i = 0; i < flow_id_1->id_len; i++)
        if (flow_id_1->id[i] != flow_id_2->id[i])
            return 0;

    return 1;
}

int picoquic_find_flow_by_fid(picoquic_cnx_t *cnx,
                              picoquic_fc_flow_id_t *flow_id)
{
    for (int i = 0; i < cnx->nb_flows; i++)
        if (picoquic_compare_flow_id(&cnx->flows[i]->flow_id, flow_id))
            return i;

    return -1;
}

int picoquic_find_flow_by_cid(picoquic_cnx_t *cnx,
                                 picoquic_connection_id_t *connection_id)
{
    return picoquic_find_flow_by_fid(cnx, (picoquic_fc_flow_id_t*)connection_id);
}

int picoquic_find_or_create_flow(picoquic_cnx_t *cnx,
                                 picoquic_fc_flow_id_t *flow_id)
{
    int i = picoquic_find_flow_by_fid(cnx, flow_id);

    if (i > 0)
        return i;

    if (cnx->nb_flows >= cnx->nb_flows_alloc) {
        if (cnx->nb_flows_alloc == 0 && (cnx->flows = calloc(1, sizeof(picoquic_fc_flow_t *)))) {
            cnx->nb_flows_alloc++;
        }
        else if ((cnx->flows = realloc(cnx->flows, (cnx->nb_flows * 2 + 1) * sizeof(picoquic_fc_flow_t *)))) {
            cnx->nb_flows_alloc = 2 * cnx->nb_flows + 1;
        }
    }

    if (cnx->flows && (cnx->flows[cnx->nb_flows] = calloc(1, sizeof(picoquic_fc_flow_t)))) {
        cnx->nb_flows++;
        return cnx->nb_flows - 1;
    }

    return -1;
}

int picoquic_update_flow(picoquic_fc_flow_t *flow,
                          picoquic_fc_flow_t *new_flow, picoquic_cnx_t *cnx,
                          uint64_t current_time)
{
    if (picoquic_compare_flow_id(&flow->flow_id, &new_flow->flow_id)) {
        if (!picoquic_compare_addr(&flow->group_addr, &new_flow->group_addr) ||
            !picoquic_compare_addr(&flow->source_addr, &new_flow->source_addr) ||
            flow->udp_port != new_flow->udp_port
        ) {
            flow->udp_port = new_flow->udp_port;
            flow->source_addr = new_flow->source_addr;
            flow->group_addr = new_flow->group_addr;

            flow->tree_joined = 0;

            cnx->need_flow_update = 1;
        }
    }
    else {
        memcpy(flow, new_flow, sizeof(picoquic_fc_flow_t));
        flow->tree_joined = 0;
        flow->join_sent = 0;
        flow->crypto_received = 0;
        flow->listen_sent = 0;
        flow->leave_required = 0;

        flow->self_sequence_number = 0;
        flow->packet_number = 0;
        flow->crypto_algo = 0;
        flow->key_len = 0;
        flow->key = NULL;

        cnx->need_flow_update = 1;

        flow->path = NULL;

        picoquic_local_cnxid_t* cid = picoquic_create_local_cnxid(cnx, 1, (picoquic_connection_id_t*)&flow->flow_id, current_time);

        if (!picoquic_compare_flow_id(&flow->flow_id, (picoquic_fc_flow_id_t *) &cid->cnx_id)) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_fc_announce);
        }
    }
    return 0; 
}

uint8_t *picoquic_prepare_fc_state_frames(
    picoquic_cnx_t *cnx, picoquic_path_t *path_x, uint8_t *bytes_next,
    uint8_t *bytes_max, int *more_data, int *is_pure_ack,
    int *is_challenge_padding_needed, uint64_t current_time,
    uint64_t *next_wake_time)
{
    if (!cnx->is_flexicast_enabled)
        return bytes_next;

    uint8_t *prev_bytes = bytes_next;

    for (int i = 0; i < cnx->nb_flows; i++) {
        if ((cnx->flows[i]->listen_sent || cnx->flows[i]->join_sent) && cnx->flows[i]->leave_required && !cnx->flows[i]->left) {
            bytes_next = picoquic_format_fc_state_frame(
                bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i],
                PICOQUIC_FC_ACTION_LEAVE);
            if (bytes_next > prev_bytes) {
                cnx->flows[i]->left = 1;
                prev_bytes = bytes_next;
            }
        }
        if (cnx->flows[i]->tree_joined && cnx->flows[i]->join_sent == 0) {
            bytes_next = picoquic_format_fc_state_frame(
                bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i],
                PICOQUIC_FC_ACTION_JOIN);
            if (bytes_next > prev_bytes) {
                cnx->flows[i]->join_sent = 1;
                prev_bytes = bytes_next;
            }
        }
        else if (cnx->flows[i]->tree_joined && cnx->flows[i]->join_sent &&
               cnx->flows[i]->crypto_received && !cnx->flows[i]->listen_sent) {
            bytes_next = picoquic_format_fc_state_frame(
                bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i],
                PICOQUIC_FC_ACTION_LISTEN);
            if (bytes_next > prev_bytes) {
                cnx->flows[i]->listen_sent = 1;
                if (cnx->flows[i]->ack_delay_timer)
                    cnx->ack_delay_remote = MIN(cnx->flows[i]->ack_delay_timer, cnx->ack_delay_remote);
                prev_bytes = bytes_next;
            }
        }
    }
    return bytes_next;
}

int picoquic_is_flexicast_address(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return (*((uint8_t *)&((struct sockaddr_in *)addr)->sin_addr.s_addr) &
                0xf0) == 0xe0;
    }
    else if (addr->sa_family == AF_INET6) {
        return *((uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr) == 0xff;
    }
    return 0;
}

uint8_t* picoquic_format_fc_leave_state_frames(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack)
{
    return bytes;
    if (cnx->is_flexicast_enabled) {
        uint8_t *prev_bytes = bytes;
        for (int i = 0; i < cnx->nb_flows; i++) {
            picoquic_fc_flow_t* flow = cnx->flows[i];
            if ((flow->listen_sent || flow->join_sent) && !flow->left) {
                flow->leave_required = 1;
                bytes = picoquic_format_fc_state_frame(bytes, bytes_max, more_data, is_pure_ack, flow, 2);
                if (bytes > prev_bytes) {
                    cnx->flows[i]->left = 1;
                    prev_bytes = bytes;
                }
            }
        }
    }
    return bytes;
}
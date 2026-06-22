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

            flow->state = picoquic_fc_cli_aware_unjoined;

            cnx->need_flow_update = 1;
        }
    }
    else {
        memcpy(flow, new_flow, sizeof(picoquic_fc_flow_t));
        flow->state = picoquic_fc_cli_aware_unjoined;

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

uint8_t *picoquic_manage_fc_cnx_frames(
    picoquic_cnx_t *cnx, picoquic_path_t *path_x, uint8_t *bytes_next,
    uint8_t *bytes_max, int *more_data, int *is_pure_ack,
    int *is_challenge_padding_needed, uint64_t current_time,
    uint64_t *next_wake_time)
{
    if (!cnx->is_flexicast_enabled)
        return bytes_next;

    uint8_t *prev_bytes = bytes_next;

    for (int i = 0; i < cnx->nb_flows; i++) {
        switch (cnx->flows[i]->state) {
        case picoquic_fc_cli_unaware:
            break;
        case picoquic_fc_cli_aware_unjoined:
            break;
        case picoquic_fc_cli_aware_unjoined_socket_ready:
            bytes_next = picoquic_format_fc_state_frame(bytes_next, bytes_max, more_data,
                is_pure_ack, cnx->flows[i], PICOQUIC_FC_ACTION_JOIN);
            if (prev_bytes > bytes_next) {
                cnx->flows[i]->state = picoquic_fc_cli_joined_no_key;
                prev_bytes = bytes_next;
            }
            break;
        case picoquic_fc_cli_joined_no_key:
            break;
        case picoquic_fc_cli_joined_w_key:
            bytes_next = picoquic_format_fc_state_frame(bytes_next, bytes_max, more_data,
                is_pure_ack, cnx->flows[i], PICOQUIC_FC_ACTION_LISTEN);
            if (prev_bytes > bytes_next) {
                cnx->flows[i]->state = picoquic_fc_cli_listening;
                prev_bytes = bytes_next;
            }
            break;
        case picoquic_fc_cli_listening:
            break;
        case picoquic_fc_cli_leaving:
            bytes_next = picoquic_format_fc_state_frame(bytes_next, bytes_max, more_data,
                is_pure_ack, cnx->flows[i], PICOQUIC_FC_ACTION_LEAVE);
            if (prev_bytes > bytes_next) {
                cnx->flows[i]->state = picoquic_fc_cli_left;
                cnx->need_flow_update = 1;
                prev_bytes = bytes_next;
            }
            break;
        case picoquic_fc_cli_left:
            break;
        case picoquic_fc_srv_unaware:
            bytes_next = picoquic_format_fc_announce_frame(bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i]);
            if (prev_bytes > bytes_next) {
                cnx->flows[i]->state = picoquic_fc_srv_aware_unjoined;
                prev_bytes = bytes_next;
            }
        case picoquic_fc_srv_aware_unjoined:
            break;
        case picoquic_fc_srv_joined_no_key:
            bytes_next = picoquic_format_fc_key_frame(bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i]);
            if (prev_bytes > bytes_next) {
                cnx->flows[i]->state = picoquic_fc_cli_joined_w_key;
                prev_bytes = bytes_next;
            }
        case picoquic_fc_srv_joined_w_key:
        case picoquic_fc_srv_listening:
        case picoquic_fc_srv_leaving:
        case picoquic_fc_srv_left:
        default:
            break;
        }
    }
    return bytes_next;
}

int picoquic_fc_state_frame_needs_repeat(picoquic_cnx_t* cnx, const uint8_t* bytes,
    const uint8_t* bytes_max, int* no_need_to_repeat)
{
    int ret = 0;
    uint64_t action = 0;
    picoquic_fc_flow_id_t flow_id;
    int i;

    *no_need_to_repeat = 0;

    if ((bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &flow_id.id_len)) == NULL ||
        (bytes = picoquic_frames_fc_flow_id_decode(bytes, bytes_max, flow_id.id_len, &flow_id)) == NULL ||
        (i = picoquic_find_flow_by_fid(cnx, &flow_id)) > 0 ||
        (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) == NULL ||
        (bytes = picoquic_frames_uint64_decode(bytes, bytes_max, &action)) == NULL
    ) {
        /* Bad frame, do not retransmit */
        *no_need_to_repeat = 1;
    }
    else {
        switch (action) {
        case PICOQUIC_FC_ACTION_JOIN:
            *no_need_to_repeat = cnx->flows[i]->state != picoquic_fc_cli_aware_unjoined;
            break;
        case PICOQUIC_FC_ACTION_LEAVE:
            *no_need_to_repeat = cnx->flows[i]->state != picoquic_fc_cli_leaving;
            break;
        case PICOQUIC_FC_ACTION_LISTEN:
            *no_need_to_repeat = cnx->flows[i]->state != picoquic_fc_cli_joined_w_key;
            break;
        default:
            *no_need_to_repeat = 0;
            break;
        }
    }
    return ret;
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
            if (picoquic_fc_cli_joined_no_key <= flow->state && flow->state <= picoquic_fc_cli_leaving) {
                flow->state = picoquic_fc_cli_leaving;
                bytes = picoquic_format_fc_state_frame(bytes, bytes_max, more_data, is_pure_ack, flow, 2);
                if (bytes > prev_bytes) {
                    flow->state = picoquic_fc_cli_left;
                    prev_bytes = bytes;
                }
            }
        }
    }
    return bytes;
}
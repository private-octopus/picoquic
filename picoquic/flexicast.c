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
#define PICOQUIC_FC_ACTION_READY 0x03

int picoquic_compare_flow_id(picoquic_fc_flow_id_t *flow_id_1,
                             picoquic_fc_flow_id_t *flow_id_2) {
  if (flow_id_1->id_len != flow_id_2->id_len)
    return 0;

  for (int i = 0; i < flow_id_1->id_len; i++) {
    if (flow_id_1->id[i] != flow_id_2->id[i])
      return 0;
  }
  return 1;
}

int picoquic_find_flow_by_fid(picoquic_cnx_t *cnx,
                                 picoquic_fc_flow_id_t *flow_id) {
  for (int i = 0; i < cnx->nb_flows; i++)
    if (picoquic_compare_flow_id(&cnx->flows[i]->flow_id, flow_id))
      return i;

  return -1;
}

int picoquic_find_flow_by_cid(picoquic_cnx_t *cnx,
                                 picoquic_connection_id_t *connection_id) {
  return picoquic_find_flow_by_fid(cnx, (picoquic_fc_flow_id_t*)connection_id);
}

int picoquic_find_or_create_flow(picoquic_cnx_t *cnx,
                                 picoquic_fc_flow_id_t *flow_id) {
  int i = picoquic_find_flow_by_fid(cnx, flow_id);
  if (i > 0)
    return i;

  if (cnx->nb_flows >= cnx->nb_flows_alloc) {
    if (cnx->nb_flows_alloc == 0 &&
        (cnx->flows = malloc(sizeof(picoquic_fc_flow_t *))))
      cnx->nb_flows_alloc++;
    else if ((cnx->flows =
                  realloc(cnx->flows,
                          cnx->nb_flows * 2 * sizeof(picoquic_fc_flow_t *))))
      cnx->nb_flows_alloc = 2 * cnx->nb_flows;
  }
  if ((cnx->flows[cnx->nb_flows] = malloc(sizeof(picoquic_fc_flow_t)))) {
    memset(cnx->flows[cnx->nb_flows], 0, sizeof(picoquic_fc_flow_t));
    cnx->nb_flows++;
    return cnx->nb_flows - 1;
  }
  return -1;
}

void picoquic_update_flow(picoquic_fc_flow_t *flow,
                          picoquic_fc_flow_t *new_flow, picoquic_cnx_t *cnx,
                          uint64_t current_time) {
  if (picoquic_compare_flow_id(&flow->flow_id, &new_flow->flow_id)) {
    if (!picoquic_compare_addr(&flow->group_addr, &new_flow->group_addr) ||
        !picoquic_compare_addr(&flow->source_addr, &new_flow->source_addr) ||
        flow->udp_port != new_flow->udp_port) {
      flow->udp_port = new_flow->udp_port;
      flow->source_addr = new_flow->source_addr;
      flow->group_addr = new_flow->group_addr;

      flow->tree_joined = 0;

      cnx->need_flow_update = 1;
    }
  } else {
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

    static const uint8_t null_seed[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t path_id = picohash_siphash(
        (uint8_t *)&flow->source_addr,
        2 * sizeof(struct sockaddr) + sizeof(uint16_t), null_seed);
    int path_index = picoquic_create_path(cnx, current_time, &flow->group_addr,
                                          &flow->source_addr, 0, path_id);

    picoquic_local_cnxid_t l_cid;
    l_cid.create_time = current_time;
    l_cid.cnx_id = *(picoquic_connection_id_t *)&flow->flow_id;
    l_cid.sequence = cnx->first_local_cnxid_list->local_cnxid_sequence_next++;
    l_cid.path_id = path_id;
    cnx->first_local_cnxid_list->nb_local_cnxid++;

    picoquic_register_cnx_id(cnx->quic, cnx, &l_cid);
    cnx->path[path_index]->receive_only_fc_flow_path = 1;
    flow->path = cnx->path[path_index];
  }
}

uint8_t *picoquic_prepare_fc_state_frames(
    picoquic_cnx_t *cnx, picoquic_path_t *path_x, uint8_t *bytes_next,
    uint8_t *bytes_max, int *more_data, int *is_pure_ack,
    int *is_challenge_padding_needed, uint64_t current_time,
    uint64_t *next_wake_time) {

  if (!cnx->is_flexicast_enabled)
    return bytes_next;

  uint8_t *prev_bytes = bytes_next;

  for (int i = 0; i < cnx->nb_flows; i++) {
    if (cnx->flows[i]->tree_joined && cnx->flows[i]->join_sent == 0) {
      bytes_next = picoquic_format_fc_state_frame(
          bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i],
          PICOQUIC_FC_ACTION_JOIN);
      if (bytes_next > prev_bytes) {
        cnx->flows[i]->join_sent = 1;
        prev_bytes = bytes_next;
      }
    } else if (cnx->flows[i]->tree_joined && cnx->flows[i]->join_sent &&
               cnx->flows[i]->crypto_received && !cnx->flows[i]->listen_sent) {
      bytes_next = picoquic_format_fc_state_frame(
          bytes_next, bytes_max, more_data, is_pure_ack, cnx->flows[i],
          PICOQUIC_FC_ACTION_READY);
      if (bytes_next > prev_bytes) {
        cnx->flows[i]->listen_sent = 1;
        prev_bytes = bytes_next;
      }
    }
  }
  return bytes_next;
}

int picoquic_is_flexicast_address(struct sockaddr *addr) {
  if (addr->sa_family == AF_INET) {
    return (*((uint8_t *)&((struct sockaddr_in *)addr)->sin_addr.s_addr) &
            0xf0) == 0xe0;
  } else if (addr->sa_family == AF_INET6) {
    return *((uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr) == 0xff;
  }
  return 0;
}
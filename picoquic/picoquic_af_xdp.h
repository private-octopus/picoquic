/*
 * AF_XDP transmit path for picoquic. RX stays on the UDP sockets.
 * GSO buffers (UDP_SEGMENT) are split into one XDP frame per segment and
 * submitted as a single TX-ring batch. Copy mode is used so a NIC queue is
 * not stolen from the kernel; another process can therefore bind a different
 * UDP port on the same interface. If AF_XDP cannot be opened, callers use
 * sendmsg, which still carries UDP_SEGMENT.
 */

#ifndef PICOQUIC_AF_XDP_H
#define PICOQUIC_AF_XDP_H

#include "picoquic_packet_loop.h"
#include "picosocks.h"

#ifdef __cplusplus
extern "C" {
#endif

const char* picoquic_tx_method_to_string(int method);

void* picoquic_af_xdp_create(int requested, int dest_if, SOCKET_TYPE udp_fd,
    int* tx_method, char* reason, size_t reason_len);

void picoquic_af_xdp_delete(void* xdp);

/*
 * Transmit one datagram or a GSO train. Returns bytes of UDP payload sent
 * (>= 1) on success, or <= 0 to request a sendmsg fallback.
 */
int picoquic_af_xdp_send(void* xdp,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from,
    int dest_if,
    const char* bytes,
    int length,
    int send_msg_size,
    int* sock_err);

#ifdef __cplusplus
}
#endif

#endif

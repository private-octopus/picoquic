#ifndef PICOQUIC_NEIGH_H
#define PICOQUIC_NEIGH_H

/*
 * Next-hop Ethernet resolution for AF_XDP TX.
 * ARP and IPv6 neighbor discovery are not XDP-specific; they live here so
 * the candidate checks can be unit tested without a socket.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Non-zero unicast MAC. The I/G bit and the all-zero address are rejected. */
int picoquic_mac_is_unicast(const uint8_t mac[6]);

/*
 * ARP cache entry is usable when ATF_COM (0x02) is set and the hardware
 * address is a unicast MAC.
 */
int picoquic_arp_entry_usable(int arp_flags, const uint8_t mac[6]);

typedef struct st_picoquic_neigh_view_t {
    int family;
    const uint8_t* dst;
    size_t dst_len;
    const uint8_t* lladdr;
    size_t lladdr_len;
} picoquic_neigh_view_t;

/* 0 and mac filled when view is the requested neighbor and has a unicast MAC. */
int picoquic_neigh_view_accept(const picoquic_neigh_view_t* view,
    int family, const uint8_t* addr, size_t addr_len, uint8_t mac[6]);

#if defined(__linux__)
int picoquic_arp_lookup(int ifindex, const uint8_t addr4[4], uint8_t mac[6]);

int picoquic_neigh_lookup(int netlink_fd, uint32_t* seq, int family,
    const uint8_t* addr, size_t addr_len, int ifindex, uint8_t mac[6]);

/*
 * Walk one netlink dump buffer.
 * Returns 0 if a valid neighbor was copied to mac, -1 on NLMSG_ERROR or
 * NLMSG_DONE, and 1 when this buffer has no match and the caller should
 * read another message.
 */
int picoquic_neigh_scan_dump(const uint8_t* buf, size_t len,
    int family, const uint8_t* addr, size_t addr_len, uint8_t mac[6]);
#endif

#ifdef __cplusplus
}
#endif

#endif

#ifndef PICOQUIC_L3TX_H
#define PICOQUIC_L3TX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ones-complement checksum over data. Used for the IPv4 header. */
uint16_t picoquic_inet_checksum(const void* data, size_t len);

/*
 * UDP checksum, including the IPv4 or IPv6 pseudo-header.
 * Ports and udp_len are in network order, as stored in a UDP header.
 * A computed checksum of 0 is returned as 0xffff.
 */
uint16_t picoquic_udp_checksum_v4(uint32_t saddr, uint32_t daddr,
    uint16_t src_port, uint16_t dst_port, uint16_t udp_len,
    const uint8_t* payload, size_t payload_len);

uint16_t picoquic_udp_checksum_v6(const uint8_t src[16], const uint8_t dst[16],
    uint16_t src_port, uint16_t dst_port, uint16_t udp_len,
    const uint8_t* payload, size_t payload_len);

#ifdef __cplusplus
}
#endif

#endif

/*
 * IPv4/IPv6 UDP checksums for the AF_XDP transmit path.
 * Split out of picoquic_af_xdp.c so they can be unit tested without a NIC.
 */

#include "picoquic_l3tx.h"

#ifdef _WINDOWS
#include "picosocks.h"
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <string.h>

static void l3tx_add_mem(uint32_t* sum, const void* data, size_t len)
{
    const uint8_t* p = (const uint8_t*)data;

    if (len == 0 || p == NULL) {
        return;
    }
    while (len > 1) {
        uint16_t word;
        memcpy(&word, p, sizeof(word));
        *sum += word;
        p += 2;
        len -= 2;
    }
    if (len) {
        uint16_t last = 0;
        memcpy(&last, p, 1);
        *sum += last;
    }
}

static uint16_t l3tx_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t l3tx_finish_udp(uint32_t sum)
{
    uint16_t c = l3tx_fold(sum);
    /* UDP checksum 0 means "no checksum". Use 0xffff for a real zero sum. */
    return c == 0 ? 0xffff : c;
}

uint16_t picoquic_inet_checksum(const void* data, size_t len)
{
    uint32_t sum = 0;
    l3tx_add_mem(&sum, data, len);
    return l3tx_fold(sum);
}

uint16_t picoquic_udp_checksum_v4(uint32_t saddr, uint32_t daddr,
    uint16_t src_port, uint16_t dst_port, uint16_t udp_len,
    const uint8_t* payload, size_t payload_len)
{
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } ph;
    uint16_t udp_head[3];
    uint32_t sum = 0;

    ph.src = saddr;
    ph.dst = daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_UDP;
    ph.len = udp_len;

    udp_head[0] = src_port;
    udp_head[1] = dst_port;
    udp_head[2] = udp_len;

    l3tx_add_mem(&sum, &ph, sizeof(ph));
    l3tx_add_mem(&sum, udp_head, sizeof(udp_head));
    l3tx_add_mem(&sum, payload, payload_len);
    return l3tx_finish_udp(sum);
}

uint16_t picoquic_udp_checksum_v6(const uint8_t src[16], const uint8_t dst[16],
    uint16_t src_port, uint16_t dst_port, uint16_t udp_len,
    const uint8_t* payload, size_t payload_len)
{
    struct {
        uint8_t src[16];
        uint8_t dst[16];
        uint32_t len;
        uint8_t zero[3];
        uint8_t nxt;
    } ph;
    uint16_t udp_head[3];
    uint32_t sum = 0;
    uint32_t ulen = 8u + (uint32_t)payload_len;

    memset(&ph, 0, sizeof(ph));
    if (src != NULL) {
        memcpy(ph.src, src, 16);
    }
    if (dst != NULL) {
        memcpy(ph.dst, dst, 16);
    }
    ph.len = htonl(ulen);
    ph.nxt = IPPROTO_UDP;

    udp_head[0] = src_port;
    udp_head[1] = dst_port;
    udp_head[2] = udp_len;

    l3tx_add_mem(&sum, &ph, sizeof(ph));
    l3tx_add_mem(&sum, udp_head, sizeof(udp_head));
    l3tx_add_mem(&sum, payload, payload_len);
    return l3tx_finish_udp(sum);
}

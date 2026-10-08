/*
 * Unit tests for the AF_XDP transmit helpers that do not need a NIC:
 * UDP checksums, unicast MAC checks, ARP cache checks, and neighbor
 * candidate selection. Creating a socket, transmitting, falling back to
 * sendmsg, and tearing the socket down need Linux, an AF_XDP-capable
 * interface, and CAP_NET_ADMIN, which CI runners do not provide.
 */

#include "picoquic_internal.h"
#include "picoquic_l3tx.h"
#include "picoquic_neigh.h"

#include <string.h>

#ifdef __linux__
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#endif

static int af_xdp_expect_wire(uint16_t got, uint8_t b0, uint8_t b1, const char* what)
{
    uint8_t wire[2];

    memcpy(wire, &got, sizeof(wire));
    if (wire[0] != b0 || wire[1] != b1) {
        DBG_PRINTF("%s checksum %02x%02x, expected %02x%02x\n", what, wire[0], wire[1], b0, b1);
        return -1;
    }
    return 0;
}

static int af_xdp_checksum_test(void)
{
    uint8_t src4[4] = { 192, 0, 2, 1 };
    uint8_t dst4[4] = { 192, 0, 2, 2 };
    uint8_t src6[16];
    uint8_t dst6[16];
    uint8_t hi[2] = { 'h', 'i' };
    uint8_t odd[3] = { 1, 2, 3 };
    uint8_t zero_sum[2] = { 0x75, 0x49 };
    uint8_t zeros[2] = { 0, 0 };
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport = htons(1234);
    uint16_t dport = htons(443);
    int i;
    int ret = 0;

    memcpy(&saddr, src4, 4);
    memcpy(&daddr, dst4, 4);
    for (i = 0; i < 16; i++) {
        src6[i] = (uint8_t)i;
        dst6[i] = (uint8_t)(i + 16);
    }

    if (af_xdp_expect_wire(picoquic_inet_checksum(zeros, sizeof(zeros)), 0xff, 0xff, "inet") != 0) {
        ret = -1;
    }
    if (af_xdp_expect_wire(
            picoquic_udp_checksum_v4(saddr, daddr, sport, dport, htons(10), hi, sizeof(hi)),
            0x0c, 0xe0, "udp4") != 0) {
        ret = -1;
    }
    if (af_xdp_expect_wire(
            picoquic_udp_checksum_v4(saddr, daddr, sport, dport, htons(11), odd, sizeof(odd)),
            0x71, 0x45, "udp4-odd") != 0) {
        ret = -1;
    }
    if (af_xdp_expect_wire(
            picoquic_udp_checksum_v4(saddr, daddr, sport, dport, htons(10), zero_sum, sizeof(zero_sum)),
            0xff, 0xff, "udp4-zero") != 0) {
        ret = -1;
    }
    if (af_xdp_expect_wire(
            picoquic_udp_checksum_v6(src6, dst6, sport, dport, htons(10), hi, sizeof(hi)),
            0x9f, 0xe3, "udp6") != 0) {
        ret = -1;
    }
    return ret;
}

static int af_xdp_mac_test(void)
{
    uint8_t uni[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t multi[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t zero[6] = { 0, 0, 0, 0, 0, 0 };
    int ret = 0;

    if (!picoquic_mac_is_unicast(uni)) {
        DBG_PRINTF("%s", "unicast MAC rejected\n");
        ret = -1;
    }
    if (picoquic_mac_is_unicast(multi) || picoquic_mac_is_unicast(bcast) ||
        picoquic_mac_is_unicast(zero) || picoquic_mac_is_unicast(NULL)) {
        DBG_PRINTF("%s", "non-unicast MAC accepted\n");
        ret = -1;
    }
    if (!picoquic_arp_entry_usable(0x02, uni)) {
        DBG_PRINTF("%s", "complete ARP entry rejected\n");
        ret = -1;
    }
    if (picoquic_arp_entry_usable(0, uni) || picoquic_arp_entry_usable(0x02, multi) ||
        picoquic_arp_entry_usable(0x02, zero)) {
        DBG_PRINTF("%s", "unusable ARP entry accepted\n");
        ret = -1;
    }
    return ret;
}

static int af_xdp_neigh_view_test(void)
{
    uint8_t addr[4] = { 192, 0, 2, 2 };
    uint8_t other[4] = { 192, 0, 2, 3 };
    uint8_t uni[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    uint8_t multi[6] = { 0x01, 0x11, 0x22, 0x33, 0x44, 0x55 };
    uint8_t got[6];
    picoquic_neigh_view_t view;
    int ret = 0;

    memset(&view, 0, sizeof(view));
    view.family = AF_INET;
    view.dst = addr;
    view.dst_len = sizeof(addr);
    view.lladdr = uni;
    view.lladdr_len = sizeof(uni);
    if (picoquic_neigh_view_accept(&view, AF_INET, addr, sizeof(addr), got) != 0 ||
        memcmp(got, uni, sizeof(uni)) != 0) {
        DBG_PRINTF("%s", "matching neighbor rejected\n");
        ret = -1;
    }
    if (picoquic_neigh_view_accept(&view, AF_INET6, addr, sizeof(addr), got) == 0 ||
        picoquic_neigh_view_accept(&view, AF_INET, other, sizeof(other), got) == 0) {
        DBG_PRINTF("%s", "wrong neighbor accepted\n");
        ret = -1;
    }
    view.lladdr = NULL;
    view.lladdr_len = 0;
    if (picoquic_neigh_view_accept(&view, AF_INET, addr, sizeof(addr), got) == 0) {
        DBG_PRINTF("%s", "neighbor without a MAC accepted\n");
        ret = -1;
    }
    view.lladdr = multi;
    view.lladdr_len = sizeof(multi);
    if (picoquic_neigh_view_accept(&view, AF_INET, addr, sizeof(addr), got) == 0) {
        DBG_PRINTF("%s", "multicast neighbor accepted\n");
        ret = -1;
    }
    return ret;
}

#ifdef __linux__
static uint32_t af_xdp_add_attr(uint8_t* buf, uint32_t msg_len, unsigned short type,
    const void* data, size_t data_len)
{
    struct rtattr* rta = (struct rtattr*)(buf + NLMSG_ALIGN(msg_len));
    rta->rta_type = type;
    rta->rta_len = (unsigned short)RTA_LENGTH(data_len);
    memcpy(RTA_DATA(rta), data, data_len);
    return (uint32_t)(NLMSG_ALIGN(msg_len) + RTA_ALIGN(rta->rta_len));
}

static uint32_t af_xdp_put_neigh(uint8_t* buf, int family, const uint8_t* addr, size_t addr_len,
    const uint8_t* mac)
{
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    struct ndmsg* ndm;

    memset(nlh, 0, NLMSG_LENGTH(sizeof(*ndm)));
    nlh->nlmsg_type = RTM_NEWNEIGH;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ndm));
    ndm = (struct ndmsg*)NLMSG_DATA(nlh);
    ndm->ndm_family = (unsigned char)family;
    nlh->nlmsg_len = af_xdp_add_attr(buf, nlh->nlmsg_len, NDA_DST, addr, addr_len);
    if (mac != NULL) {
        nlh->nlmsg_len = af_xdp_add_attr(buf, nlh->nlmsg_len, NDA_LLADDR, mac, 6);
    }
    return nlh->nlmsg_len;
}

static int af_xdp_neigh_dump_test(void)
{
    uint8_t buf[512];
    uint8_t addr[4] = { 192, 0, 2, 2 };
    uint8_t other[4] = { 198, 51, 100, 1 };
    uint8_t multi[6] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 };
    uint8_t uni[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0a };
    uint8_t got[6];
    uint32_t first;
    uint32_t second;
    struct nlmsghdr err;
    int ret = 0;

    memset(buf, 0, sizeof(buf));
    first = af_xdp_put_neigh(buf, AF_INET, other, sizeof(other), multi);
    second = af_xdp_put_neigh(buf + NLMSG_ALIGN(first), AF_INET, addr, sizeof(addr), uni);
    if (picoquic_neigh_scan_dump(buf, NLMSG_ALIGN(first) + second, AF_INET, addr, sizeof(addr), got) != 0 ||
        memcmp(got, uni, sizeof(uni)) != 0) {
        DBG_PRINTF("%s", "neighbor dump did not select the unicast match\n");
        ret = -1;
    }
    if (picoquic_neigh_scan_dump(buf, first, AF_INET, addr, sizeof(addr), got) == 0) {
        DBG_PRINTF("%s", "neighbor dump matched the wrong address\n");
        ret = -1;
    }

    memset(&err, 0, sizeof(err));
    err.nlmsg_len = sizeof(err);
    err.nlmsg_type = NLMSG_ERROR;
    if (picoquic_neigh_scan_dump((const uint8_t*)&err, sizeof(err), AF_INET, addr, sizeof(addr), got) != -1) {
        DBG_PRINTF("%s", "NLMSG_ERROR was not reported\n");
        ret = -1;
    }
    return ret;
}
#endif

int af_xdp_l3_test(void)
{
    int ret = 0;

    if (af_xdp_checksum_test() != 0 || af_xdp_mac_test() != 0 || af_xdp_neigh_view_test() != 0) {
        ret = -1;
    }
#ifdef __linux__
    if (af_xdp_neigh_dump_test() != 0) {
        ret = -1;
    }
#endif
    return ret;
}

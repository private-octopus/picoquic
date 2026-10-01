#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * IPv4 ARP and IPv6 neighbor discovery for AF_XDP TX.
 * The cache checks are pure and covered by af_xdp_l3_test. The lookups
 * themselves need a Linux routing socket.
 */

#include "picoquic_neigh.h"

#include <stdio.h>
#include <string.h>

#define PICOQUIC_ATF_COM 0x02

int picoquic_mac_is_unicast(const uint8_t mac[6])
{
    int i;
    int nz = 0;

    if (mac == NULL) {
        return 0;
    }
    for (i = 0; i < 6; i++) {
        if (mac[i] != 0) {
            nz = 1;
            break;
        }
    }
    return nz && (mac[0] & 0x01) == 0;
}

int picoquic_arp_entry_usable(int arp_flags, const uint8_t mac[6])
{
    if ((arp_flags & PICOQUIC_ATF_COM) == 0) {
        return 0;
    }
    return picoquic_mac_is_unicast(mac);
}

int picoquic_neigh_view_accept(const picoquic_neigh_view_t* view,
    int family, const uint8_t* addr, size_t addr_len, uint8_t mac[6])
{
    if (view == NULL || addr == NULL || mac == NULL || addr_len == 0) {
        return -1;
    }
    if (view->family != family || view->dst == NULL || view->dst_len < addr_len) {
        return -1;
    }
    if (memcmp(view->dst, addr, addr_len) != 0) {
        return -1;
    }
    if (view->lladdr == NULL || view->lladdr_len < 6) {
        return -1;
    }
    if (!picoquic_mac_is_unicast(view->lladdr)) {
        return -1;
    }
    memcpy(mac, view->lladdr, 6);
    return 0;
}

#if defined(__linux__)

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(ATF_COM) && ATF_COM != PICOQUIC_ATF_COM
#error "ATF_COM does not match the value checked by picoquic_arp_entry_usable"
#endif

int picoquic_arp_lookup(int ifindex, const uint8_t addr4[4], uint8_t mac[6])
{
    struct arpreq req;
    struct sockaddr_in* sin;
    char ifname[IF_NAMESIZE];
    int fd;

    if (addr4 == NULL || mac == NULL) {
        return -1;
    }
    if (if_indextoname((unsigned)ifindex, ifname) == NULL) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&req, 0, sizeof(req));
    sin = (struct sockaddr_in*)&req.arp_pa;
    sin->sin_family = AF_INET;
    memcpy(&sin->sin_addr, addr4, 4);
    snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", ifname);
    if (ioctl(fd, SIOCGARP, &req) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if (!picoquic_arp_entry_usable(req.arp_flags, (const uint8_t*)req.arp_ha.sa_data)) {
        return -1;
    }
    memcpy(mac, req.arp_ha.sa_data, ETH_ALEN);
    return 0;
}

static void neigh_nl_drain(int fd)
{
    uint8_t buf[256];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    }
}

static void neigh_msg_view(struct nlmsghdr* nlh, picoquic_neigh_view_t* view)
{
    struct ndmsg* ndm = (struct ndmsg*)NLMSG_DATA(nlh);
    int len;
    struct rtattr* rta;

    memset(view, 0, sizeof(*view));
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ndm))) {
        return;
    }
    len = (int)nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));
    rta = (struct rtattr*)((uint8_t*)ndm + NLMSG_ALIGN(sizeof(*ndm)));
    view->family = ndm->ndm_family;
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == NDA_DST) {
            view->dst = (const uint8_t*)RTA_DATA(rta);
            view->dst_len = RTA_PAYLOAD(rta);
        } else if (rta->rta_type == NDA_LLADDR) {
            view->lladdr = (const uint8_t*)RTA_DATA(rta);
            view->lladdr_len = RTA_PAYLOAD(rta);
        }
    }
}

int picoquic_neigh_scan_dump(const uint8_t* buf, size_t len,
    int family, const uint8_t* addr, size_t addr_len, uint8_t mac[6])
{
    unsigned int remain;
    int ret = 1;
    struct nlmsghdr* nlh;

    if (buf == NULL || len > 0xffffffffu) {
        return -1;
    }
    remain = (unsigned int)len;
    for (nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, remain); nlh = NLMSG_NEXT(nlh, remain)) {
        picoquic_neigh_view_t view;

        if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_DONE) {
            ret = -1;
            break;
        }
        if (nlh->nlmsg_type != RTM_NEWNEIGH) {
            continue;
        }
        neigh_msg_view(nlh, &view);
        if (picoquic_neigh_view_accept(&view, family, addr, addr_len, mac) == 0) {
            ret = 0;
            break;
        }
    }
    return ret;
}

int picoquic_neigh_lookup(int netlink_fd, uint32_t* seq, int family,
    const uint8_t* addr, size_t addr_len, int ifindex, uint8_t mac[6])
{
    uint8_t buf[8192];
    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
        char attrbuf[256];
    } req;

    if (netlink_fd < 0 || seq == NULL || addr == NULL || mac == NULL) {
        return -1;
    }
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = ++(*seq);
    req.ndm.ndm_family = (unsigned char)family;
    req.ndm.ndm_ifindex = ifindex;

    neigh_nl_drain(netlink_fd);
    if (send(netlink_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = recv(netlink_fd, buf, sizeof(buf), 0);
        int rc;
        if (n <= 0) {
            return -1;
        }
        rc = picoquic_neigh_scan_dump(buf, (size_t)n, family, addr, addr_len, mac);
        if (rc <= 0) {
            return rc;
        }
    }
}

#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

/*
 * AF_XDP TX for picoquic. Linux only. Recv stays on UDP sockets.
 */

#include "picoquic_af_xdp.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char*
picoquic_tx_method_to_string(int method)
{
    switch (method) {
    case picoquic_tx_method_af_xdp_zerocopy:
        return "AF_XDP zero-copy (GSO as TX batch)";
    case picoquic_tx_method_af_xdp_copy:
        return "AF_XDP copy (GSO as TX batch)";
    default:
        return "sendmsg";
    }
}

#if !defined(__linux__) || !defined(AF_XDP)

void*
picoquic_af_xdp_create(int requested, int dest_if, SOCKET_TYPE udp_fd,
    int* tx_method, char* reason, size_t reason_len)
{
    (void)dest_if;
    (void)udp_fd;
    if (tx_method != NULL) {
        *tx_method = picoquic_tx_method_sendmsg;
    }
    if (reason != NULL && reason_len > 0) {
        if (!requested) {
            snprintf(reason, reason_len, "not requested");
        } else {
            snprintf(reason, reason_len, "AF_XDP not built on this platform");
        }
    }
    return NULL;
}

void
picoquic_af_xdp_delete(void* xdp)
{
    (void)xdp;
}

int
picoquic_af_xdp_send(void* xdp, struct sockaddr* addr_dest, struct sockaddr* addr_from,
    int dest_if, const char* bytes, int length, int send_msg_size, int* sock_err)
{
    (void)xdp;
    (void)addr_dest;
    (void)addr_from;
    (void)dest_if;
    (void)bytes;
    (void)length;
    (void)send_msg_size;
    if (sock_err != NULL) {
#ifdef EOPNOTSUPP
        *sock_err = EOPNOTSUPP;
#elif defined(WSAEOPNOTSUPP)
        *sock_err = WSAEOPNOTSUPP;
#else
        *sock_err = -1;
#endif
    }
    return -1;
}

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP (1 << 3)
#endif
#ifndef XDP_RING_NEED_WAKEUP
#define XDP_RING_NEED_WAKEUP (1 << 0)
#endif
#ifndef IFLA_XDP
#define IFLA_XDP 43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD 1
#endif
#ifndef IFLA_XDP_FLAGS
#define IFLA_XDP_FLAGS 3
#endif
#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef BPF_PROG_TYPE_XDP
#define BPF_PROG_TYPE_XDP 6
#endif
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD 5
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif

#define PICOQUIC_XDP_FRAME_SIZE 2048
#define PICOQUIC_XDP_FRAME_COUNT 2048
#define PICOQUIC_XDP_RING_SIZE 2048
#define PICOQUIC_XDP_NEIGH_CACHE 256
#define PICOQUIC_XDP_MAX_QUEUES 128

typedef struct st_xdp_ring {
    uint32_t* producer;
    uint32_t* consumer;
    uint32_t* flags;
    void* desc;
    uint32_t mask;
    size_t desc_size;
} xdp_ring_t;

typedef struct st_xdp_neigh {
    uint32_t used;
    int family;
    uint8_t dest[16];
    uint8_t prefsrc[16];
    uint8_t dmac[ETH_ALEN];
    uint8_t smac[ETH_ALEN];
    int ifindex;
} xdp_neigh_t;

typedef struct st_picoquic_af_xdp {
    int fd;
    int netlink_fd;
    int ifindex;
    int zerocopy;
    uint8_t* umem;
    size_t umem_size;
    uint8_t* tx_map;
    size_t tx_map_size;
    uint8_t* cr_map;
    size_t cr_map_size;
    uint8_t* fq_map;
    size_t fq_map_size;
    xdp_ring_t tx;
    xdp_ring_t cr;
    xdp_ring_t fq;
    uint32_t* free_idx;
    uint32_t free_count;
    uint32_t nl_seq;
    uint8_t src_mac[ETH_ALEN];
    int src_mac_ok;
    int method;
    int refs;
    uint32_t queue_id;
    pthread_mutex_t tx_mu;
    xdp_neigh_t neigh[PICOQUIC_XDP_NEIGH_CACHE];
} picoquic_af_xdp_t;

static pthread_mutex_t xdp_global_mu = PTHREAD_MUTEX_INITIALIZER;
static picoquic_af_xdp_t* xdp_by_queue[PICOQUIC_XDP_MAX_QUEUES];
static int xdp_dummy_prog_ifindex;
static char xdp_dummy_prog_mode[16];

static int xdp_nl_open(void);
static int xdp_ifindex_from_default_route(void);

static uint16_t
xdp_checksum(const void* data, size_t len)
{
    const uint16_t* p = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) {
        uint16_t last = 0;
        memcpy(&last, p, 1);
        sum += last;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t
xdp_udp_checksum_v4(const struct iphdr* ip, const struct udphdr* udp, const uint8_t* payload, size_t payload_len)
{
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } ph;
    ph.src = ip->saddr;
    ph.dst = ip->daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_UDP;
    ph.len = udp->len;

    uint32_t sum = 0;
    const uint16_t* p = (const uint16_t*)&ph;
    for (size_t i = 0; i < sizeof(ph) / 2; i++) {
        sum += p[i];
    }
    p = (const uint16_t*)udp;
    sum += p[0];
    sum += p[1];
    sum += p[2];
    /* skip checksum field */
    p = (const uint16_t*)payload;
    size_t len = payload_len;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) {
        uint16_t last = 0;
        memcpy(&last, p, 1);
        sum += last;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t c = (uint16_t)~sum;
    return c == 0 ? 0xffff : c;
}

static uint16_t
xdp_udp_checksum_v6(const struct ip6_hdr* ip6, const struct udphdr* udp, const uint8_t* payload, size_t payload_len)
{
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t nxt;
    } ph;
    memset(&ph, 0, sizeof(ph));
    ph.src = ip6->ip6_src;
    ph.dst = ip6->ip6_dst;
    ph.len = htonl((uint32_t)(sizeof(struct udphdr) + payload_len));
    ph.nxt = IPPROTO_UDP;

    uint32_t sum = 0;
    const uint16_t* p = (const uint16_t*)&ph;
    for (size_t i = 0; i < sizeof(ph) / 2; i++) {
        sum += p[i];
    }
    p = (const uint16_t*)udp;
    sum += p[0];
    sum += p[1];
    sum += p[2];
    p = (const uint16_t*)payload;
    size_t len = payload_len;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) {
        uint16_t last = 0;
        memcpy(&last, p, 1);
        sum += last;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t c = (uint16_t)~sum;
    return c == 0 ? 0xffff : c;
}

static void
xdp_ring_init(xdp_ring_t* r, uint8_t* map_base, const struct xdp_ring_offset* off, uint32_t n, size_t desc_size)
{
    r->producer = (uint32_t*)(map_base + off->producer);
    r->consumer = (uint32_t*)(map_base + off->consumer);
    r->flags = (off->flags != 0) ? (uint32_t*)(map_base + off->flags) : NULL;
    r->desc = map_base + off->desc;
    r->mask = n - 1;
    r->desc_size = desc_size;
}

static uint32_t
xdp_ring_avail_prod(xdp_ring_t* r)
{
    uint32_t cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
    uint32_t prod = *r->producer;
    return r->mask + 1 - (prod - cons);
}

static void
xdp_recycle(picoquic_af_xdp_t* x)
{
    uint32_t prod = __atomic_load_n(x->cr.producer, __ATOMIC_ACQUIRE);
    uint32_t cons = *x->cr.consumer;
    while (cons != prod && x->free_count < PICOQUIC_XDP_FRAME_COUNT) {
        uint64_t addr = ((uint64_t*)x->cr.desc)[cons & x->cr.mask];
        x->free_idx[x->free_count++] = (uint32_t)(addr / PICOQUIC_XDP_FRAME_SIZE);
        cons++;
    }
    *x->cr.consumer = cons;
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

static int
xdp_src_mac(int ifindex, uint8_t mac[ETH_ALEN])
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    if (if_indextoname((unsigned)ifindex, ifr.ifr_name) == NULL) {
        close(fd);
        return -1;
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}

static int
xdp_iface_skip(const char* name)
{
    return strcmp(name, "lo") == 0 ||
        strncmp(name, "docker", 6) == 0 ||
        strncmp(name, "br-", 3) == 0 ||
        strncmp(name, "virbr", 5) == 0 ||
        strncmp(name, "veth", 4) == 0 ||
        strncmp(name, "cni", 3) == 0 ||
        strncmp(name, "flannel", 7) == 0;
}

static int
xdp_guess_ifindex(int dest_if)
{
    if (dest_if > 0) {
        return dest_if;
    }
    int oif = xdp_ifindex_from_default_route();
    if (oif > 0) {
        return oif;
    }
    struct if_nameindex* idx = if_nameindex();
    if (idx == NULL) {
        return 0;
    }
    int found = 0;
    for (struct if_nameindex* i = idx; i->if_index != 0; i++) {
        if (xdp_iface_skip(i->if_name)) {
            continue;
        }
        found = (int)i->if_index;
        break;
    }
    if_freenameindex(idx);
    return found;
}

static int
xdp_nl_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

static void
xdp_nl_drain_fd(int fd)
{
    uint8_t buf[256];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    }
}

static int
xdp_load_dummy_xdp_prog(void)
{
#ifdef __NR_bpf
    struct bpf_insn insns[2];
    memset(insns, 0, sizeof(insns));
    /* r0 = XDP_PASS; exit */
    insns[0].code = 0xb7;
    insns[0].imm = XDP_PASS;
    insns[1].code = 0x95;

    char license[] = "GPL";
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_XDP;
    attr.insn_cnt = 2;
    attr.insns = (uint64_t)(uintptr_t)insns;
    attr.license = (uint64_t)(uintptr_t)license;
    return (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
xdp_nl_attach_prog(int ifindex, int prog_fd, uint32_t flags)
{
    int nl = xdp_nl_open();
    if (nl < 0) {
        return -1;
    }
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        char buf[256];
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_SETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;
    req.ifm.ifi_family = AF_UNSPEC;
    req.ifm.ifi_index = ifindex;

    struct rtattr* nest = (struct rtattr*)(((uint8_t*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    nest->rta_type = (unsigned short)(IFLA_XDP | NLA_F_NESTED);
    nest->rta_len = RTA_LENGTH(0);

    struct rtattr* fd_attr = (struct rtattr*)((uint8_t*)nest + RTA_ALIGN(nest->rta_len));
    fd_attr->rta_type = IFLA_XDP_FD;
    fd_attr->rta_len = RTA_LENGTH(sizeof(int));
    memcpy(RTA_DATA(fd_attr), &prog_fd, sizeof(prog_fd));
    nest->rta_len = (unsigned short)(RTA_ALIGN(nest->rta_len) + RTA_ALIGN(fd_attr->rta_len));

    struct rtattr* fl_attr = (struct rtattr*)((uint8_t*)nest + RTA_ALIGN(nest->rta_len));
    fl_attr->rta_type = IFLA_XDP_FLAGS;
    fl_attr->rta_len = RTA_LENGTH(sizeof(uint32_t));
    memcpy(RTA_DATA(fl_attr), &flags, sizeof(flags));
    nest->rta_len = (unsigned short)(RTA_ALIGN(nest->rta_len) + RTA_ALIGN(fl_attr->rta_len));

    req.nlh.nlmsg_len = (uint32_t)((uint8_t*)nest - (uint8_t*)&req) + RTA_ALIGN(nest->rta_len);

    xdp_nl_drain_fd(nl);
    if (send(nl, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(nl);
        return -1;
    }
    uint8_t buf[512];
    ssize_t n = recv(nl, buf, sizeof(buf), 0);
    close(nl);
    if (n <= 0) {
        return -1;
    }
    for (struct nlmsghdr* nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(nlh);
            if (e->error == 0 || e->error == -EEXIST) {
                return e->error == -EEXIST ? 1 : 0;
            }
            return -1;
        }
    }
    return -1;
}

static int
xdp_attach_dummy_prog(int ifindex)
{
    if (xdp_dummy_prog_ifindex == ifindex) {
        return 0;
    }
    int prog_fd = xdp_load_dummy_xdp_prog();
    if (prog_fd < 0) {
        snprintf(xdp_dummy_prog_mode, sizeof(xdp_dummy_prog_mode), "none");
        return -1;
    }
    struct {
        uint32_t flags;
        const char* name;
    } tries[] = {
        { XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, "skb" },
        { XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, "drv" },
        { XDP_FLAGS_UPDATE_IF_NOEXIST, "native" },
    };
    int ok = -1;
    for (size_t i = 0; i < sizeof(tries) / sizeof(tries[0]); i++) {
        int rc = xdp_nl_attach_prog(ifindex, prog_fd, tries[i].flags);
        if (rc >= 0) {
            snprintf(xdp_dummy_prog_mode, sizeof(xdp_dummy_prog_mode),
                "%s", rc == 1 ? "existing" : tries[i].name);
            xdp_dummy_prog_ifindex = ifindex;
            ok = 0;
            break;
        }
    }
    close(prog_fd);
    if (ok != 0) {
        snprintf(xdp_dummy_prog_mode, sizeof(xdp_dummy_prog_mode), "none");
    }
    return ok;
}

static int
xdp_route_query_fd(int nl_fd, uint32_t* seq, int family, const uint8_t* dest, size_t dest_len,
    uint8_t* nexthop, uint8_t* prefsrc, int* oif)
{
    uint8_t buf[2048];
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char attrbuf[256];
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = ++(*seq);
    req.rtm.rtm_family = (unsigned char)family;
    req.rtm.rtm_dst_len = (unsigned char)(dest_len * 8);
    req.rtm.rtm_table = 0;

    struct rtattr* rta = (struct rtattr*)(((uint8_t*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len = (unsigned short)RTA_LENGTH(dest_len);
    memcpy(RTA_DATA(rta), dest, dest_len);
    req.nlh.nlmsg_len = (uint32_t)NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    xdp_nl_drain_fd(nl_fd);
    if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        return -1;
    }
    ssize_t n = recv(nl_fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        return -1;
    }
    memcpy(nexthop, dest, dest_len);
    memset(prefsrc, 0, dest_len);
    for (struct nlmsghdr* nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        if (nlh->nlmsg_type != RTM_NEWROUTE) {
            continue;
        }
        struct rtmsg* rtm = (struct rtmsg*)NLMSG_DATA(nlh);
        int len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
        struct rtattr* a = (struct rtattr*)((uint8_t*)rtm + NLMSG_ALIGN(sizeof(*rtm)));
        for (; RTA_OK(a, len); a = RTA_NEXT(a, len)) {
            if (a->rta_type == RTA_GATEWAY && RTA_PAYLOAD(a) >= dest_len) {
                memcpy(nexthop, RTA_DATA(a), dest_len);
            } else if (a->rta_type == RTA_PREFSRC && RTA_PAYLOAD(a) >= dest_len) {
                memcpy(prefsrc, RTA_DATA(a), dest_len);
            } else if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= 4) {
                memcpy(oif, RTA_DATA(a), sizeof(int));
            }
        }
        return 0;
    }
    return -1;
}

static int
xdp_ifindex_from_default_route(void)
{
    int fd = xdp_nl_open();
    if (fd < 0) {
        return 0;
    }
    uint32_t seq = 1;
    uint8_t dest[4] = { 1, 1, 1, 1 };
    uint8_t nh[4];
    uint8_t pref[4];
    int oif = 0;
    int rc = xdp_route_query_fd(fd, &seq, AF_INET, dest, 4, nh, pref, &oif);
    close(fd);
    if (rc != 0 || oif <= 0) {
        return 0;
    }
    char name[IF_NAMESIZE];
    if (if_indextoname((unsigned)oif, name) != NULL && xdp_iface_skip(name)) {
        return 0;
    }
    return oif;
}

static int
xdp_parse_lladdr(struct nlmsghdr* nlh, uint8_t mac[ETH_ALEN])
{
    struct ndmsg* ndm = (struct ndmsg*)NLMSG_DATA(nlh);
    int len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));
    struct rtattr* rta = (struct rtattr*)((uint8_t*)ndm + NLMSG_ALIGN(sizeof(*ndm)));
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) >= ETH_ALEN) {
            memcpy(mac, RTA_DATA(rta), ETH_ALEN);
            return 0;
        }
    }
    return -1;
}

static void
xdp_nl_drain(picoquic_af_xdp_t* x)
{
    uint8_t buf[256];
    while (recv(x->netlink_fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    }
}

static int
xdp_neigh_dst_match(struct nlmsghdr* nlh, int family, const uint8_t* addr, size_t addr_len)
{
    struct ndmsg* ndm = (struct ndmsg*)NLMSG_DATA(nlh);
    int len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));
    struct rtattr* rta = (struct rtattr*)((uint8_t*)ndm + NLMSG_ALIGN(sizeof(*ndm)));
    if (ndm->ndm_family != family) {
        return 0;
    }
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) >= addr_len &&
            memcmp(RTA_DATA(rta), addr, addr_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
xdp_neigh_query(picoquic_af_xdp_t* x, int family, const uint8_t* addr, size_t addr_len, int ifindex, uint8_t mac[ETH_ALEN])
{
    uint8_t buf[8192];
    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
        char attrbuf[256];
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = ++x->nl_seq;
    req.ndm.ndm_family = (unsigned char)family;
    req.ndm.ndm_ifindex = ifindex;

    xdp_nl_drain(x);
    if (send(x->netlink_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = recv(x->netlink_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return -1;
        }
        for (struct nlmsghdr* nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                return -1;
            }
            if (nlh->nlmsg_type == NLMSG_DONE) {
                return -1;
            }
            if (nlh->nlmsg_type == RTM_NEWNEIGH &&
                xdp_neigh_dst_match(nlh, family, addr, addr_len) &&
                xdp_parse_lladdr(nlh, mac) == 0) {
                return 0;
            }
        }
    }
}

static int
xdp_route_nexthop(picoquic_af_xdp_t* x, int family, const uint8_t* dest, size_t dest_len,
    uint8_t* nexthop, uint8_t* prefsrc, int* oif)
{
    *oif = x->ifindex;
    return xdp_route_query_fd(x->netlink_fd, &x->nl_seq, family, dest, dest_len, nexthop, prefsrc, oif);
}

static int
xdp_arp_query(int ifindex, const uint8_t* addr4, uint8_t mac[ETH_ALEN])
{
    struct arpreq req;
    struct sockaddr_in* sin;
    char ifname[IF_NAMESIZE];
    int fd;
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
#ifndef ATF_COM
#define ATF_COM 0x02
#endif
    if ((req.arp_flags & ATF_COM) == 0) {
        return -1;
    }
    memcpy(mac, req.arp_ha.sa_data, ETH_ALEN);
    {
        int i;
        int nz = 0;
        for (i = 0; i < ETH_ALEN; i++) {
            if (mac[i] != 0) {
                nz = 1;
                break;
            }
        }
        if (!nz || (mac[0] & 0x01)) {
            return -1;
        }
    }
    return 0;
}

static int
xdp_mac_unicast(const uint8_t mac[ETH_ALEN])
{
    int i;
    int nz = 0;
    for (i = 0; i < ETH_ALEN; i++) {
        if (mac[i] != 0) {
            nz = 1;
            break;
        }
    }
    return nz && (mac[0] & 0x01) == 0;
}

static int
xdp_is_loopback(const struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET) {
        uint32_t a = ntohl(((const struct sockaddr_in*)sa)->sin_addr.s_addr);
        return (a >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6*)sa)->sin6_addr);
    }
    return 0;
}

static int
xdp_is_unspecified(const struct sockaddr* sa)
{
    if (sa == NULL) {
        return 1;
    }
    if (sa->sa_family == AF_INET) {
        return ((const struct sockaddr_in*)sa)->sin_addr.s_addr == 0;
    }
    if (sa->sa_family == AF_INET6) {
        const struct in6_addr* a = &((const struct sockaddr_in6*)sa)->sin6_addr;
        if (IN6_IS_ADDR_UNSPECIFIED(a)) {
            return 1;
        }
        if (IN6_IS_ADDR_V4MAPPED(a)) {
            return a->s6_addr[12] == 0 && a->s6_addr[13] == 0 &&
                a->s6_addr[14] == 0 && a->s6_addr[15] == 0;
        }
    }
    return 0;
}

static int
xdp_connect_prefsrc(const struct sockaddr* dest, uint8_t* prefsrc, size_t addr_len)
{
    int fd;
    struct sockaddr_storage local;
    socklen_t llen = sizeof(local);
    fd = socket(dest->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (connect(fd, dest, dest->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) != 0) {
        close(fd);
        return -1;
    }
    memset(&local, 0, sizeof(local));
    if (getsockname(fd, (struct sockaddr*)&local, &llen) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if (local.ss_family == AF_INET && addr_len >= 4) {
        memcpy(prefsrc, &((struct sockaddr_in*)&local)->sin_addr, 4);
        return ((struct sockaddr_in*)&local)->sin_addr.s_addr != 0 ? 0 : -1;
    }
    if (local.ss_family == AF_INET6 && addr_len >= 16) {
        memcpy(prefsrc, &((struct sockaddr_in6*)&local)->sin6_addr, 16);
        return IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6*)&local)->sin6_addr) ? -1 : 0;
    }
    return -1;
}

static void
xdp_nudge_neigh(const struct sockaddr* dest)
{
    int fd = socket(dest->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    socklen_t alen;
    if (fd < 0) {
        return;
    }
    alen = dest->sa_family == AF_INET ? (socklen_t)sizeof(struct sockaddr_in)
                                      : (socklen_t)sizeof(struct sockaddr_in6);
    (void)sendto(fd, "", 1, MSG_DONTWAIT, dest, alen);
    close(fd);
}

static int
xdp_lookup_neigh(picoquic_af_xdp_t* x, const struct sockaddr* dest, int ifindex,
    uint8_t smac[ETH_ALEN], uint8_t dmac[ETH_ALEN], uint8_t prefsrc[16])
{
    uint8_t addr[16];
    size_t addr_len = 0;
    int family = dest->sa_family;
    memset(addr, 0, sizeof(addr));
    if (family == AF_INET) {
        addr_len = 4;
        memcpy(addr, &((const struct sockaddr_in*)dest)->sin_addr, 4);
    } else if (family == AF_INET6) {
        addr_len = 16;
        memcpy(addr, &((const struct sockaddr_in6*)dest)->sin6_addr, 16);
    } else {
        return -1;
    }

    uint32_t h = 2166136261u;
    for (size_t i = 0; i < addr_len; i++) {
        h ^= addr[i];
        h *= 16777619u;
    }
    xdp_neigh_t* e = &x->neigh[h % PICOQUIC_XDP_NEIGH_CACHE];
    if (e->used && e->family == family && e->ifindex == ifindex && memcmp(e->dest, addr, addr_len) == 0) {
        memcpy(smac, e->smac, ETH_ALEN);
        memcpy(dmac, e->dmac, ETH_ALEN);
        memcpy(prefsrc, e->prefsrc, sizeof(e->prefsrc));
        return xdp_mac_unicast(dmac) ? 0 : -1;
    }
    memset(prefsrc, 0, 16);

    if (x->src_mac_ok) {
        memcpy(smac, x->src_mac, ETH_ALEN);
    } else if (xdp_src_mac(ifindex, smac) != 0) {
        return -1;
    } else {
        memcpy(x->src_mac, smac, ETH_ALEN);
        x->src_mac_ok = 1;
    }

    uint8_t nexthop[16];
    int oif = ifindex;
    if (xdp_route_nexthop(x, family, addr, addr_len, nexthop, prefsrc, &oif) != 0) {
        /* Off-link dests must have a route. Do not XDP-send as if they were on-link. */
        return -1;
    }
    {
        int pref_unset = 1;
        size_t i;
        for (i = 0; i < addr_len; i++) {
            if (prefsrc[i] != 0) {
                pref_unset = 0;
                break;
            }
        }
        if (pref_unset) {
            (void)xdp_connect_prefsrc(dest, prefsrc, addr_len);
        }
    }
    if (oif != 0 && oif != ifindex) {
        return -1;
    }

    if (family == AF_INET && xdp_arp_query(ifindex, nexthop, dmac) == 0) {
        /* gateway (or on-link dest) from ARP */
    } else if (xdp_neigh_query(x, family, nexthop, addr_len, ifindex, dmac) != 0) {
        xdp_nudge_neigh(dest);
        if (family != AF_INET || xdp_arp_query(ifindex, nexthop, dmac) != 0) {
            if (xdp_neigh_query(x, family, nexthop, addr_len, ifindex, dmac) != 0) {
                return -1;
            }
        }
    }
    if (!xdp_mac_unicast(dmac)) {
        return -1;
    }
    e->used = 1;
    e->family = family;
    e->ifindex = ifindex;
    memcpy(e->dest, addr, sizeof(e->dest));
    memcpy(e->prefsrc, prefsrc, sizeof(e->prefsrc));
    memcpy(e->smac, smac, ETH_ALEN);
    memcpy(e->dmac, dmac, ETH_ALEN);
    return 0;
}

static size_t
xdp_build_frame(uint8_t* frame, size_t frame_max,
    const struct sockaddr* dest, const struct sockaddr* src,
    const uint8_t smac[ETH_ALEN], const uint8_t dmac[ETH_ALEN],
    const uint8_t* payload, size_t payload_len)
{
    if (frame_max < ETH_HLEN + sizeof(struct udphdr) + payload_len) {
        return 0;
    }
    struct ethhdr* eth = (struct ethhdr*)frame;
    memcpy(eth->h_dest, dmac, ETH_ALEN);
    memcpy(eth->h_source, smac, ETH_ALEN);

    uint8_t* l3 = frame + ETH_HLEN;
    struct udphdr* udp;
    size_t total;

    if (dest->sa_family == AF_INET && src != NULL && src->sa_family == AF_INET) {
        /* Write IPv4 as raw bytes. struct iphdr version/ihl bitfields are not
         * portable (ARM) and produce 0x54 instead of 0x45. */
        uint8_t* ip = l3;
        uint16_t tot_n;
        uint16_t ip_csum;
        eth->h_proto = htons(ETH_P_IP);
        memset(ip, 0, 20);
        ip[0] = 0x45;
        tot_n = htons((uint16_t)(20 + sizeof(struct udphdr) + payload_len));
        memcpy(ip + 2, &tot_n, 2);
        ip[8] = 64;
        ip[9] = IPPROTO_UDP;
        memcpy(ip + 12, &((const struct sockaddr_in*)src)->sin_addr, 4);
        memcpy(ip + 16, &((const struct sockaddr_in*)dest)->sin_addr, 4);
        ip_csum = xdp_checksum(ip, 20);
        memcpy(ip + 10, &ip_csum, 2);
        udp = (struct udphdr*)(ip + 20);
        udp->source = ((const struct sockaddr_in*)src)->sin_port;
        udp->dest = ((const struct sockaddr_in*)dest)->sin_port;
        udp->len = htons((uint16_t)(sizeof(struct udphdr) + payload_len));
        udp->check = 0;
        memcpy(udp + 1, payload, payload_len);
        {
            struct iphdr iph;
            memset(&iph, 0, sizeof(iph));
            memcpy(&iph.saddr, ip + 12, 4);
            memcpy(&iph.daddr, ip + 16, 4);
            udp->check = xdp_udp_checksum_v4(&iph, udp, payload, payload_len);
        }
        total = ETH_HLEN + 20 + sizeof(struct udphdr) + payload_len;
    } else if (dest->sa_family == AF_INET6) {
        eth->h_proto = htons(ETH_P_IPV6);
        struct ip6_hdr* ip6 = (struct ip6_hdr*)l3;
        memset(ip6, 0, sizeof(*ip6));
        ip6->ip6_flow = htonl(6 << 28);
        ip6->ip6_plen = htons((uint16_t)(sizeof(struct udphdr) + payload_len));
        ip6->ip6_nxt = IPPROTO_UDP;
        ip6->ip6_hops = 64;
        if (src != NULL && src->sa_family == AF_INET6) {
            ip6->ip6_src = ((const struct sockaddr_in6*)src)->sin6_addr;
        }
        ip6->ip6_dst = ((const struct sockaddr_in6*)dest)->sin6_addr;
        udp = (struct udphdr*)(l3 + sizeof(struct ip6_hdr));
        udp->source = (src != NULL && src->sa_family == AF_INET6) ? ((const struct sockaddr_in6*)src)->sin6_port : 0;
        udp->dest = ((const struct sockaddr_in6*)dest)->sin6_port;
        udp->len = htons((uint16_t)(sizeof(struct udphdr) + payload_len));
        udp->check = 0;
        memcpy(udp + 1, payload, payload_len);
        udp->check = xdp_udp_checksum_v6(ip6, udp, payload, payload_len);
        total = ETH_HLEN + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + payload_len;
    } else {
        return 0;
    }
    if (total < 60 && frame_max >= 60) {
        memset(frame + total, 0, 60 - total);
        total = 60;
    }
    return total;
}

static int
xdp_bind(picoquic_af_xdp_t* x, int flags)
{
    struct sockaddr_xdp sxdp;
    memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_ifindex = (uint32_t)x->ifindex;
    sxdp.sxdp_queue_id = x->queue_id;
    sxdp.sxdp_flags = (uint16_t)flags;
    return bind(x->fd, (struct sockaddr*)&sxdp, sizeof(sxdp));
}

static void
xdp_unmap_rings(picoquic_af_xdp_t* x)
{
    if (x->tx_map != NULL && x->tx_map != MAP_FAILED) {
        munmap(x->tx_map, x->tx_map_size);
    }
    if (x->cr_map != NULL && x->cr_map != MAP_FAILED) {
        munmap(x->cr_map, x->cr_map_size);
    }
    if (x->fq_map != NULL && x->fq_map != MAP_FAILED) {
        munmap(x->fq_map, x->fq_map_size);
    }
    x->tx_map = NULL;
    x->cr_map = NULL;
    x->fq_map = NULL;
    memset(&x->tx, 0, sizeof(x->tx));
    memset(&x->cr, 0, sizeof(x->cr));
    memset(&x->fq, 0, sizeof(x->fq));
}

static void
xdp_close_xsk(picoquic_af_xdp_t* x)
{
    xdp_unmap_rings(x);
    if (x->fd >= 0) {
        close(x->fd);
        x->fd = -1;
    }
}

static int xdp_open_xsk(picoquic_af_xdp_t* x, int flags);

static int
xdp_try_open_xsk(picoquic_af_xdp_t* x)
{
    /*
     * TX-only, copy mode. Zero-copy takes exclusive ownership of a NIC
     * queue pair on many drivers, so the kernel UDP sockets no longer
     * receive on that RSS queue. A second process on another UDP port
     * then goes silent when its 4-tuple hashes onto the stolen queue.
     * Copy mode keeps RX on the stack; bind is still one AF_XDP socket
     * per queue, so a second process uses the next free queue or sendmsg.
     */
    if (xdp_open_xsk(x, XDP_COPY | XDP_USE_NEED_WAKEUP) == 0 ||
        xdp_open_xsk(x, XDP_COPY) == 0) {
        x->method = picoquic_tx_method_af_xdp_copy;
        x->zerocopy = 0;
        return 0;
    }
    return -1;
}

static int
xdp_open_xsk(picoquic_af_xdp_t* x, int flags)
{
    xdp_close_xsk(x);
    x->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (x->fd < 0) {
        return -1;
    }

    struct xdp_umem_reg mr;
    memset(&mr, 0, sizeof(mr));
    mr.addr = (unsigned long long)(uintptr_t)x->umem;
    mr.len = x->umem_size;
    mr.chunk_size = PICOQUIC_XDP_FRAME_SIZE;
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) != 0) {
        return -1;
    }

    int ndescs = PICOQUIC_XDP_RING_SIZE;
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_FILL_RING, &ndescs, sizeof(ndescs)) != 0 ||
        setsockopt(x->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ndescs, sizeof(ndescs)) != 0 ||
        setsockopt(x->fd, SOL_XDP, XDP_TX_RING, &ndescs, sizeof(ndescs)) != 0) {
        return -1;
    }

    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) != 0) {
        return -1;
    }

    x->tx_map_size = off.tx.desc + PICOQUIC_XDP_RING_SIZE * sizeof(struct xdp_desc);
    x->cr_map_size = off.cr.desc + PICOQUIC_XDP_RING_SIZE * sizeof(uint64_t);
    x->fq_map_size = off.fr.desc + PICOQUIC_XDP_RING_SIZE * sizeof(uint64_t);
    x->tx_map = mmap(NULL, x->tx_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, x->fd, XDP_PGOFF_TX_RING);
    x->cr_map = mmap(NULL, x->cr_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, x->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    x->fq_map = mmap(NULL, x->fq_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, x->fd, XDP_UMEM_PGOFF_FILL_RING);
    if (x->tx_map == MAP_FAILED || x->cr_map == MAP_FAILED || x->fq_map == MAP_FAILED) {
        if (x->tx_map == MAP_FAILED) {
            x->tx_map = NULL;
        }
        if (x->cr_map == MAP_FAILED) {
            x->cr_map = NULL;
        }
        if (x->fq_map == MAP_FAILED) {
            x->fq_map = NULL;
        }
        return -1;
    }
    xdp_ring_init(&x->tx, x->tx_map, &off.tx, PICOQUIC_XDP_RING_SIZE, sizeof(struct xdp_desc));
    xdp_ring_init(&x->cr, x->cr_map, &off.cr, PICOQUIC_XDP_RING_SIZE, sizeof(uint64_t));
    xdp_ring_init(&x->fq, x->fq_map, &off.fr, PICOQUIC_XDP_RING_SIZE, sizeof(uint64_t));

    if (xdp_bind(x, flags) != 0) {
        return -1;
    }
    return 0;
}

static void
xdp_set_reason(char* reason, size_t reason_len, const char* text)
{
    if (reason != NULL && reason_len > 0 && text != NULL) {
        snprintf(reason, reason_len, "%s", text);
    }
}

static void
xdp_free_instance(picoquic_af_xdp_t* x)
{
    if (x == NULL) {
        return;
    }
    xdp_close_xsk(x);
    if (x->netlink_fd >= 0) {
        close(x->netlink_fd);
        x->netlink_fd = -1;
    }
    if (x->umem != NULL && x->umem != MAP_FAILED) {
        munmap(x->umem, x->umem_size);
    }
    pthread_mutex_destroy(&x->tx_mu);
    free(x->free_idx);
    free(x);
}

static picoquic_af_xdp_t*
xdp_new_unbound(int ifindex, char* reason, size_t reason_len)
{
    picoquic_af_xdp_t* x = (picoquic_af_xdp_t*)calloc(1, sizeof(*x));
    if (x == NULL) {
        xdp_set_reason(reason, reason_len, "out of memory");
        return NULL;
    }
    x->fd = -1;
    x->netlink_fd = -1;
    x->ifindex = ifindex;
    x->refs = 1;
    x->umem_size = (size_t)PICOQUIC_XDP_FRAME_SIZE * PICOQUIC_XDP_FRAME_COUNT;
    pthread_mutex_init(&x->tx_mu, NULL);
    x->free_idx = (uint32_t*)malloc(sizeof(uint32_t) * PICOQUIC_XDP_FRAME_COUNT);
    if (x->free_idx == NULL) {
        xdp_set_reason(reason, reason_len, "out of memory");
        xdp_free_instance(x);
        return NULL;
    }
    for (uint32_t i = 0; i < PICOQUIC_XDP_FRAME_COUNT; i++) {
        x->free_idx[i] = i;
    }
    x->free_count = PICOQUIC_XDP_FRAME_COUNT;

    x->umem = mmap(NULL, x->umem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (x->umem == MAP_FAILED) {
        x->umem = NULL;
        xdp_set_reason(reason, reason_len, "umem mmap failed");
        xdp_free_instance(x);
        return NULL;
    }

    x->netlink_fd = xdp_nl_open();
    if (x->netlink_fd < 0) {
        xdp_set_reason(reason, reason_len, "netlink socket failed");
        xdp_free_instance(x);
        return NULL;
    }
    x->src_mac_ok = (xdp_src_mac(ifindex, x->src_mac) == 0);
    return x;
}

void*
picoquic_af_xdp_create(int requested, int dest_if, SOCKET_TYPE udp_fd,
    int* tx_method, char* reason, size_t reason_len)
{
    (void)udp_fd;
    if (tx_method != NULL) {
        *tx_method = picoquic_tx_method_sendmsg;
    }
    if (!requested) {
        xdp_set_reason(reason, reason_len, "not requested");
        return NULL;
    }

    int ifindex = xdp_guess_ifindex(dest_if);
    if (ifindex <= 0) {
        xdp_set_reason(reason, reason_len, "no usable interface");
        return NULL;
    }

    pthread_mutex_lock(&xdp_global_mu);

    if (xdp_attach_dummy_prog(ifindex) != 0) {
        xdp_set_reason(reason, reason_len,
            "XDP program attach failed; using sendmsg");
        pthread_mutex_unlock(&xdp_global_mu);
        return NULL;
    }

    for (uint32_t q = 0; q < PICOQUIC_XDP_MAX_QUEUES; q++) {
        if (xdp_by_queue[q] != NULL) {
            continue;
        }
        picoquic_af_xdp_t* x = xdp_new_unbound(ifindex, reason, reason_len);
        if (x == NULL) {
            pthread_mutex_unlock(&xdp_global_mu);
            return NULL;
        }
        x->queue_id = q;
        if (xdp_try_open_xsk(x) == 0) {
            xdp_by_queue[q] = x;
            if (tx_method != NULL) {
                *tx_method = x->method;
            }
            {
                char ok[160];
                char ifname[IF_NAMESIZE];
                if (if_indextoname((unsigned)ifindex, ifname) == NULL) {
                    snprintf(ifname, sizeof(ifname), "?");
                }
                snprintf(ok, sizeof(ok), "ifindex=%d (%s) queue=%u xdp-prog=%s",
                    ifindex, ifname, q,
                    xdp_dummy_prog_mode[0] != '\0' ? xdp_dummy_prog_mode : "none");
                xdp_set_reason(reason, reason_len, ok);
            }
            pthread_mutex_unlock(&xdp_global_mu);
            return x;
        }
        int err = errno;
        xdp_free_instance(x);
        if (err != EBUSY && err != EADDRINUSE && err != EEXIST) {
            /* No such queue, or a hard failure. Stop scanning if the NIC
             * rejected this queue id; still allow sharing below. */
            if (err == ENODEV || err == EINVAL) {
                break;
            }
        }
    }

    for (uint32_t q = 0; q < PICOQUIC_XDP_MAX_QUEUES; q++) {
        picoquic_af_xdp_t* x = xdp_by_queue[q];
        if (x == NULL || x->ifindex != ifindex) {
            continue;
        }
        x->refs++;
        if (tx_method != NULL) {
            *tx_method = x->method;
        }
        {
            char ok[160];
            char ifname[IF_NAMESIZE];
            if (if_indextoname((unsigned)ifindex, ifname) == NULL) {
                snprintf(ifname, sizeof(ifname), "?");
            }
            snprintf(ok, sizeof(ok), "ifindex=%d (%s) queue=%u shared refs=%d xdp-prog=%s",
                ifindex, ifname, x->queue_id, x->refs,
                xdp_dummy_prog_mode[0] != '\0' ? xdp_dummy_prog_mode : "none");
            xdp_set_reason(reason, reason_len, ok);
        }
        pthread_mutex_unlock(&xdp_global_mu);
        return x;
    }

    xdp_set_reason(reason, reason_len, "AF_XDP bind failed: Device or resource busy");
    pthread_mutex_unlock(&xdp_global_mu);
    return NULL;
}

void
picoquic_af_xdp_delete(void* xp)
{
    picoquic_af_xdp_t* x = (picoquic_af_xdp_t*)xp;
    if (x == NULL) {
        return;
    }
    pthread_mutex_lock(&xdp_global_mu);
    x->refs--;
    if (x->refs > 0) {
        pthread_mutex_unlock(&xdp_global_mu);
        return;
    }
    if (x->queue_id < PICOQUIC_XDP_MAX_QUEUES && xdp_by_queue[x->queue_id] == x) {
        xdp_by_queue[x->queue_id] = NULL;
    }
    pthread_mutex_unlock(&xdp_global_mu);
    xdp_free_instance(x);
}

int
picoquic_af_xdp_send(void* xp,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from,
    int dest_if,
    const char* bytes,
    int length,
    int send_msg_size,
    int* sock_err)
{
    picoquic_af_xdp_t* x = (picoquic_af_xdp_t*)xp;
    struct sockaddr_in dest4;
    struct sockaddr_in src4;
    struct sockaddr* dest_sa = addr_dest;
    struct sockaddr* src_sa = addr_from;

    if (x == NULL || addr_dest == NULL || bytes == NULL || length <= 0) {
        if (sock_err != NULL) {
            *sock_err = EINVAL;
        }
        return -1;
    }

    if (addr_dest->sa_family == AF_INET6 && addr_dest != NULL) {
        const struct sockaddr_in6* a6 = (const struct sockaddr_in6*)addr_dest;
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
            memset(&dest4, 0, sizeof(dest4));
            dest4.sin_family = AF_INET;
            dest4.sin_port = a6->sin6_port;
            memcpy(&dest4.sin_addr, &a6->sin6_addr.s6_addr[12], 4);
            dest_sa = (struct sockaddr*)&dest4;
            if (addr_from != NULL && addr_from->sa_family == AF_INET6) {
                const struct sockaddr_in6* s6 = (const struct sockaddr_in6*)addr_from;
                memset(&src4, 0, sizeof(src4));
                src4.sin_family = AF_INET;
                src4.sin_port = s6->sin6_port;
                memcpy(&src4.sin_addr, &s6->sin6_addr.s6_addr[12], 4);
                src_sa = (struct sockaddr*)&src4;
            } else if (addr_from != NULL && addr_from->sa_family == AF_INET) {
                src_sa = addr_from;
            }
        }
    }

    if (src_sa == NULL || dest_sa->sa_family != src_sa->sa_family) {
        if (sock_err != NULL) {
            *sock_err = EINVAL;
        }
        return -1;
    }

    if (xdp_is_loopback(dest_sa)) {
        if (sock_err != NULL) {
            *sock_err = ENETUNREACH;
        }
        return -1;
    }

    pthread_mutex_lock(&x->tx_mu);

    int ret = -1;
    int ifindex = x->ifindex;
    if (dest_if > 0 && dest_if != x->ifindex) {
        if (sock_err != NULL) {
            *sock_err = ENETUNREACH;
        }
        goto out;
    }

    uint8_t smac[ETH_ALEN];
    uint8_t dmac[ETH_ALEN];
    uint8_t prefsrc[16];
    memset(prefsrc, 0, sizeof(prefsrc));
    if (xdp_lookup_neigh(x, dest_sa, ifindex, smac, dmac, prefsrc) != 0) {
        if (sock_err != NULL) {
            *sock_err = ENETUNREACH;
        }
        goto out;
    }

    struct sockaddr_in src_fix4;
    struct sockaddr_in6 src_fix6;
    if (xdp_is_unspecified(src_sa)) {
        if (dest_sa->sa_family == AF_INET) {
            memset(&src_fix4, 0, sizeof(src_fix4));
            src_fix4.sin_family = AF_INET;
            src_fix4.sin_port = ((const struct sockaddr_in*)src_sa)->sin_port;
            memcpy(&src_fix4.sin_addr, prefsrc, 4);
            if (src_fix4.sin_addr.s_addr == 0) {
                goto out;
            }
            src_sa = (struct sockaddr*)&src_fix4;
        } else if (dest_sa->sa_family == AF_INET6) {
            memset(&src_fix6, 0, sizeof(src_fix6));
            src_fix6.sin6_family = AF_INET6;
            src_fix6.sin6_port = ((const struct sockaddr_in6*)src_sa)->sin6_port;
            memcpy(&src_fix6.sin6_addr, prefsrc, 16);
            if (IN6_IS_ADDR_UNSPECIFIED(&src_fix6.sin6_addr)) {
                goto out;
            }
            src_sa = (struct sockaddr*)&src_fix6;
        }
    }

    int seg = send_msg_size > 0 ? send_msg_size : length;
    int nseg = (length + seg - 1) / seg;
    xdp_recycle(x);
    if (nseg <= 0 || x->free_count < (uint32_t)nseg || xdp_ring_avail_prod(&x->tx) < (uint32_t)nseg) {
        if (sock_err != NULL) {
            *sock_err = EAGAIN;
        }
        goto out;
    }

    int offset = 0;
    uint32_t prod = *x->tx.producer;
    uint32_t saved_free = x->free_count;
    for (int i = 0; i < nseg; i++) {
        int chunk = length - offset;
        if (chunk > seg) {
            chunk = seg;
        }
        uint32_t idx = x->free_idx[--x->free_count];
        uint8_t* frame = x->umem + (size_t)idx * PICOQUIC_XDP_FRAME_SIZE;
        size_t flen = xdp_build_frame(frame, PICOQUIC_XDP_FRAME_SIZE, dest_sa, src_sa,
            smac, dmac, (const uint8_t*)bytes + offset, (size_t)chunk);
        if (flen == 0) {
            x->free_count = saved_free;
            if (sock_err != NULL) {
                *sock_err = EINVAL;
            }
            goto out;
        }
        struct xdp_desc* d = &((struct xdp_desc*)x->tx.desc)[prod & x->tx.mask];
        d->addr = (uint64_t)idx * PICOQUIC_XDP_FRAME_SIZE;
        d->len = (uint32_t)flen;
        d->options = 0;
        prod++;
        offset += chunk;
    }
    /* Copy-mode TX often silently drops frames unless an XDP program is attached. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    *x->tx.producer = prod;
    (void)sendto(x->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    ret = length;
out:
    pthread_mutex_unlock(&x->tx_mu);
    return ret;
}

#endif

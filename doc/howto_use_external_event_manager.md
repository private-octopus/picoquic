# Integrating Picoquic with an External Event Manager

This guide explains how to drive Picoquic from a custom event loop (for example `libevent`, `libuv`, `Boost.Asio`, or a proprietary reactor) instead of relying on the built-in socket loop. The goal is to let your existing networking stack own the UDP sockets, timers, and threading model while Picoquic focuses on QUIC state management.

The workflow is split into four responsibilities:

1. **Socket readiness** – your event manager detects readable and writable UDP sockets.
2. **Packet ingestion** – readable datagrams are passed to Picoquic via `picoquic_incoming_packet_ex` so that encryption, connection lookup, and protocol handling occur (`picoquic/packet.c:2369`).
3. **Packet production** – whenever the QUIC stack has data to send (or a stateless response queued), the event loop fetches datagrams from `picoquic_prepare_next_packet_ex` and writes them to the network (`picoquic/sender.c:4227`).
4. **Timer management** – the loop schedules wake-ups based on `picoquic_get_next_wake_delay`, ensuring PTOs, connection timeouts, and retransmissions fire on time (`picoquic/quicctx.c:1433`).

The sections below show a complete integration pattern, including a reference implementation using `libevent` in C.

## 1. Picoquic Context Lifecycle

Picoquic exposes a single context object (`picoquic_quic_t`) that owns connections, buffers, and alarms. Create it once during initialization and keep a pointer in your loop context. Typical initialization mirrors the sample client setup (`sample/sample_client.c:456-540`), where ALPN, callbacks, and TLS material are configured before entering the packet loop. When the event loop is shutting down, call `picoquic_free(quic)` to release memory.

```c
#include "picoquic.h"
#include "picoquic_config.h"

static picoquic_quic_t *create_quic_context(void) {
    picoquic_quic_config_t config;
    picoquic_config_init(&config);   /* zero-initialize + defaults */
    config.nb_connections = 64;
    config.do_retry = 0;
    config.alpn = "hq-29";        /* pick the ALPN negotiated with peers */
    config.sni = "example.com";   /* optional, but typical for client contexts */

    picoquic_quic_t *quic = picoquic_create_and_configure(&config,
        /* default callback */ NULL, NULL,
        picoquic_current_time(), NULL);

    picoquic_config_clear(&config);
    return quic;
}
```

Keep the returned pointer in your event-loop state. All subsequent calls (`picoquic_prepare_next_packet_ex`, `picoquic_incoming_packet_ex`, `picoquic_get_next_wake_delay`) require this handle.

## 2. Owning UDP Sockets in the Event Loop

Picoquic’s socket loop allocates up to four sockets and performs send/receive inside `picoquic_packet_loop_cb_fn` callbacks (`picoquic/picoquic_packet_loop.h:74-143`). When integrating with an external manager, you control the sockets directly:

1. Create one or more UDP sockets and bind them to the desired local addresses.
2. Set them to non-blocking mode.
3. Register read events with the event manager so that the loop is notified when datagrams arrive.

Your callback should read all available packets,
defined as the entire payload of an UDP packet (it might include several coalesced QUIC packets).
For each datagram, call `picoquic_incoming_packet_ex` with the raw bytes, source/destination addresses,
interface index (if available), ECN bits, and the current timestamp (`picoquic/packet.c:2369`).

### Example: Read Callback Skeleton

```c
static void on_quic_datagrams(struct quic_loop_ctx *ctx, evutil_socket_t fd) {
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage addr_from = {0};
    struct sockaddr_storage addr_local = {0};
    socklen_t addr_from_len = sizeof(addr_from);
    socklen_t addr_local_len = sizeof(addr_local);
    unsigned char received_ecn = 0;

    for (;;) {
        struct msghdr msg = {0};
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer)
        };

        uint8_t cmsg_buf[128];
        msg.msg_name = &addr_from;
        msg.msg_namelen = addr_from_len;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        ssize_t nb = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (nb < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* Drained */
            }
            perror("recvmsg");
            break;
        }

        picoquic_cnx_t *first_cnx = NULL;
        uint64_t now = picoquic_current_time();
        (void)picoquic_incoming_packet_ex(ctx->quic, buffer, (size_t)nb,
            (struct sockaddr*)&addr_from, (struct sockaddr*)&addr_local,
            /* if_index_to */ 0, received_ecn, &first_cnx, now);
    }
}

static void on_udp_read(evutil_socket_t fd, short what, void *arg) {
    struct quic_loop_ctx *ctx = arg;
    on_quic_datagrams(ctx, fd);
    quic_schedule_send(ctx);
}
```

The helper `quic_schedule_send` (shown later) pushes pending data toward the network by polling `picoquic_prepare_next_packet_ex`.

## 3. Scheduling Timers with `picoquic_get_next_wake_delay`

QUIC correctness depends on accurate PTO (Probe Timeout) timers. Picoquic exposes `picoquic_get_next_wake_delay`, which returns how long the stack can sleep before it must run again (`picoquic/quicctx.c:1433`). A typical integration stores a periodic timer event in the loop and re-arms it after every send/receive:

```c
static void on_timeout(evutil_socket_t fd, short what, void *arg) {
    struct quic_loop_ctx *ctx = arg;
    quic_schedule_send(ctx); /* Ensure PTO probes are emitted */
    quic_reschedule_timer(ctx);
}

static void quic_reschedule_timer(struct quic_loop_ctx *ctx) {
    const int64_t delay_max_us = 1000 * 1000; /* clamp to 1 second */
    uint64_t now = picoquic_current_time();
    int64_t delay = picoquic_get_next_wake_delay(ctx->quic, now, delay_max_us);
    struct timeval tv = {
        .tv_sec = (time_t)(delay / 1000000),
        .tv_usec = (suseconds_t)(delay % 1000000)
    };
    evtimer_add(ctx->timer_event, &tv);
}
```

Call `quic_reschedule_timer` once after creating the QUIC context and again after every send or receive so the timer adapts to new wake-ups.

## 4. Producing Packets for Transmission

Whenever the UDP socket becomes writable (or immediately after processing inbound packets), call `picoquic_prepare_next_packet_ex`. The function returns either a stateless packet (retry/close) or the next connection’s datagram (`picoquic/sender.c:4227`). You pass in buffers and Picoquic fills in the destination address and interface index.

```c
static void quic_schedule_send(struct quic_loop_ctx *ctx) {
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage addr_to = {0};
    struct sockaddr_storage addr_from = {0};
    size_t send_length = 0;
    int if_index = 0;
    picoquic_connection_id_t log_cid = picoquic_null_connection_id;
    picoquic_cnx_t *last_cnx = NULL;

    for (;;) {
        int ret = picoquic_prepare_next_packet_ex(ctx->quic, picoquic_current_time(),
            send_buffer, sizeof(send_buffer), &send_length,
            &addr_to, &addr_from, &if_index, &log_cid, &last_cnx, NULL);

        if (ret != 0 || send_length == 0) {
            break; /* Nothing to send now */
        }

        ssize_t nb = sendto(ctx->udp_fd, send_buffer, send_length, 0,
            (struct sockaddr*)&addr_to, (socklen_t)picoquic_addr_length((struct sockaddr*)&addr_to));
        if (nb < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Re-arm writable notification and retry later. */
                break;
            }
            perror("sendto");
            break;
        }
    }

    quic_reschedule_timer(ctx);
}
```

After each iteration, continue polling until `send_length` becomes zero so that stateless packets and retransmissions are flushed immediately. The helper `picoquic_addr_length` computes the correct `socklen_t` for IPv4 or IPv6 destinations, matching the utility used throughout the built-in socket loop (`picoquic/util.c:541`).

### Handling Multiple Paths or Alternate Ports

If your application binds multiple sockets (for multipath or alternate ports), call `picoquic_prepare_next_packet_ex` once per writable socket and respect the returned `addr_from` / interface hints. Packet production is coordinated with each path’s congestion controller during `picoquic_prepare_packet_ex`, which chooses the path tuple providing the datagram (`picoquic/sender.c:4055`).

## 5. End-to-End Example with libevent

The following excerpt shows a minimal integration tying the previous pieces together. Error handling and TLS initialization are condensed for clarity.

```c
struct quic_loop_ctx {
    picoquic_quic_t *quic;
    evutil_socket_t udp_fd;
    struct event *read_event;
    struct event *timer_event;
};

static void on_udp_read(evutil_socket_t fd, short what, void *arg);
static void on_timeout(evutil_socket_t fd, short what, void *arg);

static struct quic_loop_ctx *quic_loop_start(struct event_base *base, const struct sockaddr *bind_addr) {
    struct quic_loop_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->quic = create_quic_context();

    ctx->udp_fd = socket(bind_addr->sa_family, SOCK_DGRAM, 0);
    evutil_make_socket_nonblocking(ctx->udp_fd);
    bind(ctx->udp_fd, bind_addr, (socklen_t)picoquic_addr_length(bind_addr));

    ctx->read_event = event_new(base, ctx->udp_fd, EV_READ | EV_PERSIST, on_udp_read, ctx);
    event_add(ctx->read_event, NULL);

    ctx->timer_event = evtimer_new(base, on_timeout, ctx);
    quic_reschedule_timer(ctx);

    return ctx;
}

static void on_udp_read(evutil_socket_t fd, short what, void *arg) {
    struct quic_loop_ctx *ctx = arg;
    on_quic_datagrams(ctx, fd);      /* Uses picoquic_incoming_packet_ex */
    quic_schedule_send(ctx);         /* Uses picoquic_prepare_next_packet_ex */
}

static void on_timeout(evutil_socket_t fd, short what, void *arg) {
    struct quic_loop_ctx *ctx = arg;
    quic_schedule_send(ctx);
}
```

The helper `on_quic_datagrams` is the function shown earlier in §2. The timer callback simply asks Picoquic for data—if nothing is ready the timer will be re-armed based on the next wake delay.

### Integrating a Custom Wake Mechanism

If your event manager hosts Picoquic in a background thread, pair the previous pattern with the wake-up helpers provided in `picoquic_packet_loop.h`. The thread-safe entry points wrap the callbacks used by the socket loop:

- `picoquic_start_network_thread` launches a dedicated Picoquic networking thread and accepts custom thread primitives (`picoquic/picoquic_packet_loop.h:166-197`).
- `picoquic_wake_up_network_thread` triggers a `picoquic_packet_loop_wake_up` callback so your thread can signal new data or configuration (`picoquic/picoquic_packet_loop.h:150-155`).

Even when using those helpers, the send/receive logic remains the same: your event manager feeds UDP packets in and out of `picoquic_incoming_packet_ex` and `picoquic_prepare_next_packet_ex` while honoring the timers returned by `picoquic_get_next_wake_delay`.

## 6. Additional Considerations

### ECN and Ancillary Data

`picoquic_incoming_packet_ex` accepts an ECN codepoint so that congestion controllers such as L4S or Prague can react to marks (`picoquic/packet.c:2376`). If your network stack surfaces ECN values, translate them into the `received_ecn` byte before calling Picoquic. Similarly, you can decode interface indices or destination addresses from `recvmsg` control data and fill the `addr_to`/`if_index` arguments.

### Stateless Packets and Logging

Because `picoquic_prepare_next_packet_ex` checks the stateless packet queue first (`picoquic/sender.c:4233`), your integration automatically handles Retry, Version Negotiation, and close frames even before a connection is fully created. Ensure your event loop sends every datagram returned by the API—even during connection setup or DoS mitigation.

### Packet Coalescing and Maximum MTU

For best throughput, keep the send buffer at least `PICOQUIC_MAX_PACKET_SIZE` bytes. Picoquic will coalesce multiple QUIC packets into a single UDP datagram when GSO is available (`picoquic/sockloop.c:1006`), but falling back to standard `sendto` still works—the function simply returns the exact length to transmit.

### Error Handling and Connection Cleanup

If `picoquic_prepare_next_packet_ex` returns an error, inspect the connection (`last_cnx`) and call `picoquic_close` or `picoquic_free` as needed. Connection states progress through `picoquic_state_client_ready`, `picoquic_state_disconnected`, etc., just as they do in the built-in loop (`sample/sample_client.c:380`).

## 7. Checklist

1. Instantiate the QUIC context once at startup.
2. Register UDP sockets with your event manager and pass received datagrams into `picoquic_incoming_packet_ex`.
3. Poll `picoquic_prepare_next_packet_ex` after every receive or wake-up and send any returned datagrams immediately.
4. Reschedule a timer using `picoquic_get_next_wake_delay` so PTOs trigger correctly.
5. Use Picoquic’s logging (`picoquic_log_packet`) or your own instrumentation to monitor traffic.

Following these steps yields the same behavior as Picoquic’s internal socket loop while letting you reuse the rest of your networking infrastructure.

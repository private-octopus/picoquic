# Picomask, implementation of Masque in Picoquic

The Masque working group has defined a series of protocols for tunneling
various types of packets into QUIC, including for example Ethernet frames
of IP packets. The implementation of tunneling inside Picoquic
focuses on tunneling UDP packets, so QUIC connections could be
tunneled through a proxy. There are three tunneling methods defined by
the Masque WG:

* Proxying UDP in HTTP: [RFC9298](https://datatracker.ietf.org/doc/rfc9298/)
* Proxying Bound UDP in HTTP: [internet draft](https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-listen/)
* QUIC-Aware Proxying Using HTTP: [internet draft](https://datatracker.ietf.org/doc/draft-ietf-masque-quic-proxy/)

The UDP proxying draft expects that the client will specify the IP address
and UDP port to which packets will be forwarded. With that service, a
four tuple (local IP, local port, peer IP, peer port) can
only be used by one proxied connection at a time. On one hand, that
allows simple implementations, but it requires opening many UDP sockets,
which is not quite in line with the architecture of picoquic. According
to the draft, packets arriving at the proxy are only forwarded to the
client if they come from the specified 4-tuple. This provides some
security, as the client will not receive packets from unexpected
sources, but it also prevent QUIC servers from using the proxy.

The "bound UDP" draft lifts the 4-tuple restriction. The proxy will
open a UDP port for the client, and forward to the client all packets
arriving to that port. It allows the proxy client to run a QUIC server,
at the cost of two small deployment issues: the server must manage
multiple UDP ports and allow every one of them through the firewall,
and only one of the proxy or
the remote servers can use a standard port like 443.

The "QUIC aware" draft solves the port sharing problem for client connections.
Packets arriving to the server are demultiplexed using the Connection Identifier.
However, this demultiplexing imposes coordinating the usage of connection
identifiers between clients and servers, which makes the solution
more complex. The forwarding mode of the QUIC aware draft avoids double
encryption of data packets. It limits the transmission overhead, and allows for
cascading of several proxies without additional "per proxy" overhead.

The QUIC Aware mode is only designed to support proxying of client
connections. This is insufficient for peer-to-peer applications, which may
need a proxy to cross NAT or firewalls. Solving that requires extending the
proxy to understand incoming "initial" packets that carry a random "initial
connection identifier" -- probably using the SNI in the "Client Hello"
packets.

## Proxying API

The proxying API enables the deployment of a variety of Masque protocols.

When a Masque protocol is used, the packets are forwarded to the proxy
as datagrams, using a datagram prefix negotiated by the proxy protocol.
The sending flow should be:

- If there is something to send by the proxy, the "intercept" API
  will be used to call the "proxy prepare a packet" API instead
  of asking the stack to prepare the next quic packet.
- The proxy code will prepare the set of bytes needed for the
  next proxied data. If a QUIC connection is being proxied, that
  may involve asking the QUIc code to prepare the next packet
  for that connection.
- The packet will be encapsulated in a datagram on the
  QUIC connection between the QUIC stack and the proxy.
- The proxy decapsulates the packet, processes the
  incoming datagram, and forwards the content of the datagram
  according to proxying rules -- for example, forward the
  content as a payload through the specified UDP port.

The receiving flow should be:

- Data arrives to the proxy. For example, if proxying UDP, a new
  datagram is received.
- The data is queued until the proxying connection can process
  it. It is then sent as a QUIC datagram to the selected client.
- Client receives a QUIC datagram, decapsulates it,
  and submits it as "incoming data" to the proxy context. If
  proxying QUIC connection, the packet is processed as
  an incoming packet.

This requires a set of APIs:

- On the client, if the proxy connection is ready to send a
  datagram, it asks the proxy code to produce it. This is
  similar to the "prepare next packet" API, but only called
  from within the "prepare datagram" module. It should return
  length and timer.
- On the client, upon receiving a proxy datagram, it should
  be passed to the "incoming data" API of the proxy. Same on
  the proxy.
- On the proxy, if the proxy connection is ready to send
  datagrams, it should check the various proxy contexts
  and pick the next one.

Issues specific to UDP proxying:

Proxying UDP implies listening to the UDP socket that's being proxied,
differentiating the packets bound to a proxy service from other QUIC packets,
and forwarding the content according to proxy rule. That implies
filtering the "incoming packet" API to detect whether it should
be managed by the proxy. We thus need:

- managing a filter on the proxy side to check whether the
  proxy wants this packet

Issues specific to QUIC proxying:

A QUIC connection may use a proxy for one of its paths. If a path
is managed by a proxy, the connection should inform the proxy when
data is ready to send on that path, and wait for the "prepare packet"
call from the proxy to send data on that path. This could be
done by considering the proxy as a special interface.



```
typedef int (*picoquic_proxy_intercept_fn)(void* proxy_ctx, uint64_t current_time,
    uint8_t* send_buffer, size_t send_length, size_t send_msg_size,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int if_index);

typedef void (*picoquic_proxy_forwarding_fn)(void* proxy_ctx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    picoquic_cnx_t** p_last_cnx, size_t* send_msg_size);

typedef int (*picoquic_proxy_proxying_fn)(
    void* proxy_ctx, uint8_t* bytes, size_t length,
    struct sockaddr* addr_from, struct sockaddr* addr_to, int if_index_to,
    unsigned char received_ecn, uint64_t current_time);

typedef void(*picoquic_proxying_free_fn)(void* proxy_ctx);
```

The proxying code implements functions according to each of these prototypes. When
the application starts, the proxying code "hooks" into the picoquic stack by calling:

```
void picoquic_set_proxying(picoquic_quic_t * quic,
    picoquic_proxy_intercept_fn intercept_fn, picoquic_proxy_forwarding_fn forwarding_fn, 
    picoquic_proxy_proxying_fn proxying_fn, picoquic_proxying_free_fn proxy_free_fn, void* proxy_ctx);
```

### Interception

The interception function `picoquic_proxy_intercept_fn` is used to capture packets 
sent to a masque proxy. It is called inside the lower layer API
`picoquic_prepare_next_packet_ex` (See Prepare API in the
architecture document). The logic is as follow:

* the networking component calls `picoquic_prepare_next_packet_ex`,
* code in that component formats a train of packet in the `sendbuffer`,
* the code calls the function `picoquic_prepare_next_packet_ex` provided by
  the proxy.
* the proxy examines the packets. If it decides to take charge of
  these packets and forward them, if fill return "True" (i.e., 1),
  and the code in `picoquic_prepare_next_packet_ex` will continue
  and try to prepare the next packet. Otherwise, the function
  returns 0 and the packet train is sent normally, without proxying.

### Forwarding

The forwarding function `picoquic_proxy_forwarding_fn` is also called from
within the lower layer API `picoquic_prepare_next_packet_ex`. The proxy
will format packets into the provided buffer, and these packets will
be sent through the normal sockets.

### Proxying

The proxying function is called from the API `picoquic_incoming_packet`,
doing pretty much the reverse of the "intercept" API. When a
packet arrives from a peer:

* the networking component calls `picoquic_incoming_packet`,
* the code in `picoquic_incoming_packet` calls the function
  `picoquic_proxy_forwarding_fn` provided by the proxy,
* the proxy examines the incoming packet and decides whether
  to process it, in which case it returns 1, or to let the
  normal incoming code run, in which case it returns 0.

These packets will then be forwarded as QUIC datagrams
* on the connection to the proxy, or as obfuscated datagrams if the proxying is
* QUIC aware. The intercept function returns 1 if the packet was intercepted,
* 0 if it wasn't.

### Freeing the resource

The code in `picoquic_free` will call `picoquic_proxying_free_fn` to let the
proxying code rease its resource when the QUIc context is being released.


## Implementation

The implementation of Masque in Picoquic focuses on two services: UDP connect,
for clients, and  Bound UDP, for servers.

### Content of QUIC datagrams

Packets are carried in QUIC datagrams, between client and servers. All HTTP datagrams
start by a "quarter stream ID" that identifies the stream context over which the
extended Connect was sent, following by a context ID.

* for UDP Connect, the context ID is always 0, and the content is the UDP payload.
  The IP address of the peer is tied to the control stream.

* for UDP Listen, the context ID 0 carries IP version, IP address, UDP Port number,
  and UDP payload. The context ID larger that 0 carry only the UDP payload,
  because the context ID is mapped to an IP address and a port number.

When QUIC aware "forwarding" is defined for UDP Connect, short head packets can be sent in forwarded
mode -- UDP datagrams in which a "virtual CID" replaces the original CID of the forwarded packet. Long
header packets are always sent as QUIC/HTTP datagrams.

### QUIC Aware Listen

QUIC Awareness is based a CID exchange defined over capsules. The client sends Connection ID
capsules registering Client CID and Target CID. In the simplest form, without forwarding, the
CID are used by the proxy to find the proxy context associated with a datagram. This allows
sharing of a proxy port by multiple UDP Connect connections. This exchange could be used
"as is" for UDP listen.

We cannot assume that all packets sent by targets carry a registered CID. The
Initial packets used to setup the connection will use a random Initial CID instead.
QUIC aware listening will require proxy to process the incoming initial packets to obtain the
SNI and use it to associate the incoming packet with one of the clients, or with a local service.
This in turn requires a management protocol to associate SNIs with clients in a secure way.

### Forwarding protocol

The forwarding protocol is a by-product of CID registration. If an endpoint is ready
to send a packet as a QUIC datagram, the packet has a short header, and the CID is
registered, the packet can be relayed as a UDP datagram instead of a QUIC datagram.
This has three advantages:

* fixed overhead, even if multiple relays are used
* use of a simple transform instead of double encryption
* no interference with congestion control, as the proxied UDP datagrams are not
  sent as part of the proxy connection.

This forwarding can happen in Listen mode just as it happens in Connect mode.

### Triaging incoming packets

How about:

* if CID is known, derive connection from CID
    - for connect UDP or listen UDP, the QUIC context already has a list of expected CID
    - if the QUIC aware extension is negotiated, more will be known
* if CID is not known:
    - if QUIC aware, this can be an initial packet. Route based on SNI.
    - it could also be a race condition. But then drop is acceptable.
    - Else, derive context from target address for port (but what if just one port?)

Look at special CID cases, e.g., RETRY packets
Look at handling of stateless reset.

Can we start with the table quic->table_cnx_by_id?



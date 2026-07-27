# Performance testing with picoquicdemo

The picoquic library includes support for the "Standard Communication with Network Elements Protocol",
[SCONE](https://datatracker.ietf.org/doc/draft-ietf-scone-protocol/). SCONE enables client and server to
obtain advice on the long term data rate supported by a network path. When SCONE is enabled:

* the client sets the last two bytes of the first initial packet to the SCONE indicator value
  `0xc813`, so the SCONE capable network elements can detect that the QUIC flow on
  the selected IP addresses and ports will support SCONE.
* client and server prepend a SCONE packet in front of regular packets, with a
  frequency sufficent to ensure several such packets in any give 67 seconds interval.
* if the intermediate routers are SCONE acapable, they update the "SCONE advice" in
  the SCONE packet to indicate the long term supported data rate of the connection.

In picoquic, the support is negotiated by using the option "-5" in the command line
configuration or by setting the default version of the transport parameter `is_scone_supported`
to 1 in the QUIC context, prior to the establishment of the connection. This will have
the following effects:

* if the parameter is set on the client side, the client will set the SCONE indicator
  in the first Initial packet of the connection.
* if the negotiation of transport parameter shows support for SCONE by both client and
  server, both endpoints will send SCONE packets at random intervals, computed as:
  `19s + random(0..3s)`.
* when an endpoint receives a valid SCONE packet containing a SCONE advice, picoquic
  will signal that advice using a callback `picoquic_callback_scone_indication`. The
  advice, computed in bits/s, is acrried in the `stream_id` parameter of the callback,
  and the `length` parameter of the callback is set to the unique path ID of the
  path to which the advice applies.

These rules differ slightly from the negotiation specified in the SCONE. SCONE specifies
that endpoints start sending SCONE packets as soon as they receive an indication that
their peer will accept them. The picoquic implementation is a bit more restrictive:
client will only send SCONE packets if the two endpoints support SCONE. If either
endpoint declines to support SCONE, no SCONE packets will be send.

The reason for this deviation is to manage potential deployment blockers. We have learned
that some firewalls parse QUIC packets and drop them if they contain a packet header that
the firewall do not understand. Picoquic is programmed to retransmit the packet contents,
so the connection will not break, but the dropping of packets will impact the connection's
performances. Endpoint located behind this kind of firewall can minimize the performance
impact by not configuring support for SCONE.

SCONE specifies that the SCONE indicator is set on "the UDP datagrams that commence a new flow".
Picoquic will only set the indicator in the first of these datagrams, and will not set it
if these initial datagrams need to be repeated. Again, this is a precaution against
firewalls that may react wrongly and drop packets that contain content that they do not
expect. The way picoquic is behaving, these firewalls may drop the first packet, but they
will not have any reason to drop the following repetitions.

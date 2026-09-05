# Zero RTT

Zero Round Trip Time (RTT) is the possibility
for the client to send data to the server before the connection is fully
established. It allows for faster exchange of data between client and server
but carries some risk. It is supported by picoquic, in fact enabled by default.
Data sent as zero RTT could be replayed by attackers. using zero RTT
requires two precautions:

- application servers that receive data before the callback `picoquic_callback_ready`
  must treat that data as a potential replay attack, and should delay the
  processing of sensitive transactions until the callback is received.

- application clients should wait until receiving the callback
  `picoquic_callback_almost_ready` before starting sensitive transactions.

To understand risks and proctection, we will start by reviewing the basic
connection setup, present the zero RTT mechanism, present the replay
attack against zero RTT exchanges, and discuss the protection against
that attack.

## The session setup without 0RTT

```
Connection prepares
and sends message
                        ----------> (1)
                                      Server validates message,
                                      sends response
                                    (2)
                   (3) <----------
Client verifies the
server message,
sends validation
                   (4)  ---------->
                                    (5)
                                      Server accepts
                                      validation, sends
                                      Handshake Done message.
                                    (6)
                       <-----------
                   (7)
Client knows that
server is ready.
```

The figure above provides a very raw description of the QUIC connection
setup, which embeds the setup of a TLS 1.3 session 
(see [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html).
In this exchange, the parties progressively negotiate keys:

1. The server learns the identifiant of the connection and the
   keying material chosen by the client.
2. The server choses its own keying material, compute
   the corresponding handshake and application data key,
   and sends a response that includes a server certificate
   and a signature. 
3. The client computes the handshake and session key,
   and verifies the server signature and certificate.
4. The client has validated the key exchange, sends a
   final TLS message.
5. The server receives the final TLS message from the
   client and validates it.
6. The server can receive application data.

This succession of steps provides a series of guarantees:

- After step (3), the client knows that the server has accepted
  the connection, but cannot tell whether a "man in the middle"
  attacker has been intercepting and relaying messages.
- After verifying the server signature and certicate at step (4),
  the client is assured that it has an end to end connection with
  the expected server.
- After validating the client final message at step (6), the
  server knows that the client has validated the connection.

The client can only send and receive application data after step (4),
which happens at least one Round Trip Time (RTT) after starting the
connection. The "zero RTT" process allows to speed up the data
transfer.

The server can send application data after step (2), but does not
know yet whether that data will be accepted by the client, or whether
some forgery happens. It will only know that at step (6).

Picoquic uses two callbacks to inform the application about the
state of the connection:

- `picoquic_callback_almost_ready`: Data can be sent, but the connection is not fully established.
- `picoquic_callback_ready`: Data can be sent and received, connection migration can be initiated.

These callbacks happen at different points in the exchange on the server
and on the client:

| Callback  | Server | Client |
|-----------|--------|--------|
| Almost Ready | After step (2) | After step (4) |
| Ready | After step (6) | After step (7) |

If she session is not enabling Zero RTT, all incoming data callback
for datagrams and streams will happen after the "almost ready"
callback on the client, and after the "ready" callback on the
server.

## The Zero RTT process

The Zero RTT process allows the client to send data
before that, if the initial client message contains a "session
resume ticket" acquired during a previous connection. The ticket
is associated with a "secret" established during that previous connection.

```
Connection prepares
and sends message,
including resume ticket
                        ----------> (1)
                                      Server validates message,
                                      verifies resume ticket
                                      sends response
                                    (2)
Client sends 0RTT data
                  (1z) -----------> (2z)
                                      Server accepts 0RTT data
                   (3) <----------
Client verifies the
server message,
sends validation
Client knows whether
0RTT was accepted.
                   (4)  ---------->
                                    (5)
                                      Server accepts
                                      validation
                                    (6)
                       <-----------
                   (7)
Client knows that
server is ready.
```


If the ticket is valid, the client can send data immediately
(point (1z) in the diagram), without waiting for arrival of
the server response. The data will be delivered by the server
as it arrives.

The picoquic client sends zero RTT data using the same mechanisms
as 1RTT data, using APIs like `picoquic_add_to_stream`,
`picoquic_mark_active_stream`, `picoquic_queue_datagram_frame`
or `picoquic_mark_datagram_ready`. If the resume ticket enabled
zero RTT, the data will be sent as zero RTT. If it did not, or
if there was no ticket, the data will only be sent when the
TLS exchange is complete, i.e., after step (4).

There is always a possibility that the ticket used by the
client is not accepted by the server. The client learns
that by processing the server TLS messages, i.e., just
before step (4). If that happens, the packets sent as zero RTT
are considered lost, and the data that they contained will be resent
after step (4).

The application can assess whether zero RTT was enabled by
calling the API `picoquic_is_0rtt_available` after receiving
the almost ready callback.

## The Zero RTT replay attack {#attack}

Attackers may be able to listen to previous 0RTT enabled
exchanges and replay them. The initial exchange will fail,
because the attacker do not have access to the secret associated
with the session resume ticket, but the replayed 0RTT
data may still be received.

```
Attacker replays
initial message,
including resume ticket
                        ----------> (1)
                                      Server validates message,
                                      verifies resume ticket
                                      sends response
                                    (2)
                   (3) <----------
Attacker replays
0RTT data
                  (1z) -----------> (2z)
                                      Server accepts 0RTT data
                                      Server may send data
                                      before step (5)
                       <----------
```

The risk depends on the nature of the data sent in the
zero RTT packets that the attacker replays. If the client
only sent inocuous data, such as "GET homepage", there is
little consequence apart from wasting server cycles. But not
all data is inocuous, as discussed in 
[Section 5.6 of RFC 9001](https://www.rfc-editor.org/info/rfc9001/#section-5.6).
A worst case example would be for example a banking transaction that,
if repeated, would repeat a payment. The recommendation to
only send inocuous data or perform "idempotent" transactions
is also developed in 
[Section 3.1 of RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html#name-replay-attacks).

Picoquic relies on [picotls](https://github.com/h2o/picotls) to apply the
[freshness checks described in
section 8.3 of RFC9846](https://www.rfc-editor.org/rfc/rfc9846.html#name-freshness-checks),
which limit to 10 seconds the maximum time during which an attacket can replay
the initial message of a zero RTT connection. Of course, limiting the
time during which tickets can be replayed does not completely
eliminate the risk of replay

Server applications can use the `picoquic_callback_ready` callback to differentiate
between data sent before and after the TLS session is complete. Data received
before theis callback was sent by the client as zero RTT. Servers should apply
application specific protections to only process "idempotent" or "inocuous"
transactions before that callback. Data received before that callback was sent
by the client as zero RTT. Picoquic deletes the zero RTT encryption keys
just before issuing this callback on the server, so zero RTT data is never accepted
or submitted to the application after that callback is issued.

Data queued by the client after the callback `picoquic_callback_almost_ready`
will always be sent as 1RTT data, and cannot be replayed by attackers.



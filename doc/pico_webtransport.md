# Pico Web Transport

Implementation of the web transport protocol on top of picoquic and h3zero implementation of HTTP3.

## Pico Web Transport architecture

The web transport implementation runs on top of the "h3zero" implementation of HTTP3,
which itself runs on top of Quic/picoquic. The application interfaces with the web transport
API, and receives data through a callback. 

~~~
+-----------------------+                    +-----------------------+
| client app            |                    | server app            |
| H3zero API / Callback |                    | H3zero API / Callback |
|   |             ^     |                    |   |             ^     |
+---|-------------|-----+                    +---|-------------|-----+
    |             |                              |             |
+---|-------------|-----+                    +---|-------------|-----+
|   v             |     |                    |   v             |     |
|H3zero/WebTransport    |                    |H3zero/WebTransport    |
|Picoquic API / Callback|                    |Picoquic API / Callback|
|   |             ^     |                    |   |             ^     |
+---|-------------|-----+                    +---|-------------|-----+ 
    |             |                              |             |
+---|-------------|-----+                    +---|-------------|-----+
|   v             |     |                    |   v             |     |
|      Picoquic         |                    |      Picoquic         |
+-----------------------+                    +-----------------------+
~~~

The web transport server is actually an HTTP server, augmented with support for
web transport primitives. Establishing a web transport connection requires
first establishing an HTTP3 connection, handled by the H3zero server code,
then using the "Connect Web transport" method on the client to "upgrade" the
HTTP3 connection to a web transport connection. Client and server can then open
QUIC streams, over which they run the protocol of their choice.

## Life time of sessions

A session starts when the client issues a "connect" request, or when a server receives and accepts it.

The session state is an object of type `picowt_session_ctx-t`, which is allocated by the application
on the client side, and automatically by the server on the server side. The allocation is recorded in
the table of stream prefixes in the H3Zero connection context. The table is keyed by the ID of the control
stream for the session.

The session state is deleted when the entry for the control stream is removed from the table of stream
prefixes. The stack or the application can do that at anytime.

If the session state is deleted, all corresponding streams will be closed, or reset.

## Per stream context

The application can attach a per stream context to the H3 stream context. This can be done at any time.
The application will be informed of stream closures, and must manage the memory allocated for the context.

## Web transport callback API

The web transport callback API is implemented in H3zero.


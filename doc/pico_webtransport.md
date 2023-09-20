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
HTTP3 connection to a web transport connection. The connect request is sent
over a QUIC/HTTP3 stream. That stream needs to remain open for the
duration of the session -- closing it closes the session.

Client and server can then open QUIC streams, over which they run the protocol
of their choice. The QUIC streams opened by web transport start with a "stream
prefix", which differentiate them from regular HTTP3 streams. For web transport,
the stream prefix is set to the identifier of the "control stream", i.e., the
stream over which the connect request was sent. The HTTP3 server processes the
incoming streams. It will direct these streams to a web transport session if it
recognizes their prefix, or treat them as regular HTTP traffic otherwise.

There is state attached to sessions, such as remembering open streams. In the picoquic
Web Transport implementation, the session state is an object of type
`picowt_session_ctx-t`, which is allocated by the application
on the client side when starting the connect call, and created by the server on the server
side when processing that call. The allocation is recorded in
the table of stream prefixes in the H3Zero connection context. The table is keyed
by the ID of the control stream for the session.

### Preparing an H3 server to accept Web Transport sessions

To support web transport, a server must be ready to accept H3 connections, and then
configured to accept web transport connections over that. There is an example of such
code in the `quic__server` function of `picoquic_demo.c`. To simplify, the
requirements are:

 * Prepare a picoquic context ready to accept HTTP3 requests. In `picoquicdemo`, 
   this is done by setting the callback to `picoquic_demo_server_callback`,
   defined in `demoserver.c`. That callback provides support for 4 different
   protocols: HTTP3, HTTP/0.9, SIDUCK and QUICPERF. If you only want to support
   HTTP3, you can set the callback function to `picoquic_h09_server_callback`.

 * Configure the HTTP3 server to accept and process Web Transport requests by
   configuring a "path table". Each path specifies a local URL, a path callback
   function, and a path callback context, per `picohttp_server_path_item_t`
   in `h3zero_common.h`.

 * Run the server socket loop connected to the picoquic context.

### Setting Web Transport sessions on a client

To set up a web transport connection, the client needs to first create a
connection to the target web server, then attach a web transport session
to that connection. In picoquic, this requires:

 * Creating a client side quic context
 * 
 * Creating a connection with the ALPN set to "H3" and the callback
   set to `h3zero_callback` defined in `h3zero_common.h`.

 * Create a stream in the connection.
 
 * Call the API `picowt_connect` defined in `pico_webtransport.h`
 
 * Run the server socket loop connected to the picoquic context.

The function `wt_baton_client` in `baton_app_.c` provides an example of a
web transport client.

## Web transport API

The web transport application will interact with the web transport and the
QUIC stack in three ways:

 * Setting up the Web Transport context by calling `picowt_connect` on the
   client,

 * Opening and closing streams,

 * Responding to "path" callbacks from the web stack.

### Web transport callback

The web transport callback API is defined as `picohttp_post_data_cb_fn`
in `h3zero_common.h`. The enumeration `picohttp_call_back_event_t`
defines the following callback events:

~~~
        picohttp_callback_get, /* Received a get command */
        picohttp_callback_post, /* Received a post command */
        picohttp_callback_connecting, /* Sending out a connect command */
        picohttp_callback_connect, /* Received a connect command */
        picohttp_callback_connect_refused, /* Connection request was refused by peer */
        picohttp_callback_connect_accepted, /* Connection request was accepted by peer */
        picohttp_callback_post_data, /* Data received from peer on stream N */
        picohttp_callback_post_fin, /* All posted data have been received on this stream */
        picohttp_callback_provide_data, /* Stack is ready to send chunk of data on stream N */
        picohttp_callback_post_datagram, /* Datagram received on this context */
        picohttp_callback_provide_datagram, /* Ready to send datagram in this context */
        picohttp_callback_reset, /* Stream has been abandoned by peer. */
        picohttp_callback_deregister, /* Context has been deregistered */
        picohttp_callback_free
~~~

The callback definition is generic -- it is used for any kind of web server
extension defined by connecting an URL path with a processor. Apart from
web transport, it is currently used to process HTTP Post requests. That's
why the list includes the `get` and `post` events, which are not used by
web transport.

An example of callback implementation is provided in `wt_baton_callback`
in `wt_baton.c`._

### Creating streams

An example of stream creation is provided in `wt_baton_create_stream`
in `wt_baton.c`. The steps are:

 * Find the next available stream number, using the API `picoquic_get_next_local_stream_id`

 * Create an HTTP3 stream context, of type `picohttp_server_stream_ctx_t`,
   by using the API `h3zero_find_or_create_stream` defined in `h3zero_common.h`.

 * Create the application context for the stream

 * Create the appropriate stream header

 * push the header bytes on the stream using `picoquic_add_to_stream_with_ctx`

Subsequent interactions with the stream will be through the callback API.



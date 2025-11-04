# Supporting multiple application protocols

If the exe manages just one application protocol, life is simple: just declare the
ALPN and the corresponding callback when creating the QUIC context. For example,
in the sample server, the QUIC context is opened as:

~~~
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_callback, &default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);
~~~

If a client starts a connection, it will only succeed if the ALPN matches the expected
value, "picoquic_sample", all connection events will be served through the callback
function "sample_server_callback", and the callback context will be set to "default_context"
for all connections. But if we want the exe to listen for multiple applications protocols,
this is getting more complicated:

- each of these application protocols is identified by a different ALPN,
- each protocol typically uses its own callback to handle connection events,
- each connection will be initialized with an appropriate "default context".

We can see that mechanism at play in "picoquic demo", which supports several applications
protocols such as H3, HTTP/0.9, or QPERF. The QUIC context of the demo server is 
initialized with a default "protocol neutral" callback, declared as:

~~~
   qserver = picoquic_create_and_configure(config, picoquic_demo_server_callback,
       &picoquic_file_param, current_time, NULL);
~~~

Critically, this does not specify a "default ALPN" for the QUIC context.
Then, the picoquicdemo code declares an "ALPN Selector" function:

~~~
   picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn);
~~~
The function type is declared in picoquic.h:

~~~
    typedef size_t (*picoquic_alpn_select_fn)(picoquic_quic_t* quic, ptls_iovec_t* list, size_t count);
~~~

That function will be called when processing an incoming connection, passing the QUIC
context of the server and the list of  "count" ALPN proposed by the client, each represented
by an iovec (tuple pointer and length). The function will return the index of the selected
iovec, or a value >= count if none matches (in which case the connection will fail).

So, when a new connection arrives, it gets configured with an ALPN, but the callback and the
callback context are set to a generic value. The first event for the new connection will
call that default callback function, which in the case of picoquicdemo first get the
"logical" value of the ALPN (because, for example, "h3" could also be specified as
"h3-29" or "h3-33" or whatever equivalent draft number), and then performs the corresponding
callback, "h3zero_callback", "quicperf_callback" or "picoquic_h09_server_callback".

In our implementation, each of these callback notices that they are being called with
the default context value, and immediately allocates and initialize an appropriate
context for the new connection -- see for example the code in the first lines of
"h3zero_callback".

If you want to design an application running either native or over web transport, you will
need to provide something equivalent:

* an "ALPN Selector" function that recognize "h3" and the ALPN chosen for the "native" app,

* a default call back that will call either "h3zero_callback" or the appropriate
  callback for the native application,

In the native callback, the code should recognize the "first call" and reset the
context as appropriate. The code should also declare the web transport protocol,
including declaration of the H3 "path" and the provision of a web transport callback.

In the case of webtransport compatible native applications, we could probably provide a
generic implementation that acts as a shim layer between native QUIC events and the
web transport callback, so the application developer only has to provide the ALPN
of the native APP and the web transport callback. But that's not done yet...

# Pico Web Transport

Implementation of the web transport protocol on top of picoquic and h3zero implementation of HTTP3.

# Life time of sessions

A session starts when the client issues a "connect" request, or when a server receives and accepts it.

The session state is an object of type `picowt_session_ctx-t`, which is allocated by the application
on the client side, and automatically by the server on the server side. The allocation is recorded in
the table of stream prefixes in the H3Zero connection context. The table is keyed by the ID of the control
stream for the session.

The session state is deleted when the entry for the control stream is removed from the table of stream
prefixes. The stack or the application can do that at anytime.

If the session state is deleted, all corresponding streams will be closed, or reset.

# Per stream context

The application can attach a per stream context to the H3 stream context. This can be done at any time.
The application will be informed of stream closures, and must manage the memory allocated for the context.

# Key functions


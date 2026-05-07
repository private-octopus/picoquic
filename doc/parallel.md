# Running picoquic on multiple threads in parallel

Picoquic was initially designed as a singled threaded module,
with the assumption that
deployments requiring higher performance would simply run multiple instances
of picoquic in multiple parallel processes. Per developper demand, we have
extended it with support for multithread operations:


- Support for multiple network threads
- Support for "shared" UDP ports in the socket loop
- Support for thread specific port
- Support for Preferred Address redirection
- Software option to verify proper use of the picoquic API in threaded environments

With these new features, developers can "scale up" deployments of services that
use picoquic, using multiple servers, multiple processes or multiple threads.

## Supported architectures

We support three variants of parallelism: multiple threads in a single process,
multiple processes, and multiple hosts. Each of these variants use one or all
of the features listed above:

| Feature | Multiple threads | Multiple processes | Multiple hosts |
|---------|------------------|--------------------|----------------|
| Multiple network threads | Yes | No | Maybe |
| Shared UDP port | Yes | Yes | Yes |
| Thread specific port | Yes | Yes | Yes |
| Preferred address migration | Yes | Yes | Yes |
| API usage check | Yes | No | Maybe |

## Starting multiple threads

The default socket loop can be started either "in line", as a single separate thread,
or as multiple threads. Each thread is started by calling the function
`picoquic_start_network_thread`:

```
picoquic_network_thread_ctx_t* picoquic_start_network_thread(
    picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx,
    int * ret);
```

When starting multiple threads, the application shall use a separate quic context,
and a separate "param" structure for each thread. 

The network thread launched by `picoquic_start_network_thread` will use the
default thread handling functions for the local operating system. Applications
that want different functions can use `picoquic_start_custom_network_thread`
to pass pointers to these functions.

## Support for shared UDP ports

The deployments assume that external peers see a single system,
a single combination of IP address and UDP port. Whether the
system uses multiple threads, multiple processes or multiple
hosts, we end up with the same problem: select a host, a process
or a thread to handle the UDP connection, and making sure that
all packets used by that connection are processed by the
same thread.

The thread creation function documents the use of a shared port
in the `param` structure, which has the following members:

```
typedef struct st_picoquic_packet_loop_param_t {
    uint16_t local_port; /* Default port for outgoing connection */
    int local_af;
    int dest_if;
    uint16_t public_port;
    int is_port_shared;
    int socket_buffer_size;
    int do_not_use_gso;
    int extra_socket_required;
    int prefer_extra_socket;
    int simulate_eio;
    size_t send_length_max;
} picoquic_packet_loop_param_t;
```

These arguments describe the sockets that need to be created.
The "local port" is used for outgoing connections, and is not
shared with any other thread. The "public port" is used for
incoming connections; for a web server it will typically
be set to 443. If "is port shared" is set to a non zero value,
the socket will be opened with the "SO_REUSEADDRESS" option,
and the "SO_REUSEPORT" option if supported by the OS.


## Thread specific port and preferred address migration

The default behavior of the Linux stack is to distribute packets to
sockets bound to the same address and port using a 4-tuple hash.
The allocation of hashes to hash bucket should remain stable for
the duration of the initial handshake, but there is no guarantee
that it will remain stable fot the entire duration of a long
running connection.

The QUIC specification specifies a "preferred address migration"
that allows a server to migrate an incoming connection to a
"preferred address". The server document its preferred addresses
(IPv4 and IPv6) and port number in a transport parameter, and the
client migrates to one of these addresses as soon as the handshake
completes.

TODO: how does it work.



## API usage in multithread environments

As noted in the introduction, the picoquic APIs are not thread safe.
It is important that the API is only used in the same thread that
also handles the picoquic context and the attached connection.
In many scenarios, the developers will want to have at least two threads:
one managing the application, and another managing the picoquic
stack. The requirement then is to perform all API calls from within
the network thread. In more complex scenarios, the process may manage
several application threads and several network thread. There will
be a picoquic context and a set of connections for each thread.
The requirement in that case is to perform all API calls from within
the same network thread that manages the relevant connection
or the QUIC context.

~~~
   +-----------------------------------------------------------+
   |                   +---------------------------------+     |
   |                   | +---------------------------------+   |
   | +--------------+  | | +---------------------------------+ |
   | | application  |  | | | Network thread                  | |
   | |  thread(s)   |  | | |                                 | |
   | |  wake-up  ?--------->       Wait loop                 | |
   | |  function ?-------> |            |                    | |
   | |           ?-----> | |       +----+-----+ packets,     | |
   | |              |  | | |       |          | timers       | |
   | |              |  | | | +-----v----+ +---v------------+ | |
   | |  Handler <-------------> Wake up | | Picoquic stack | | |
   | |              |  | | | | callback | |                | | |
   | |              |  | | | |     ------->                | | |
   | |              |  | | | +----------+ |                | | |
   | |              |  | | | +----------+ |                | | |
   | |              |  | | | | Callback | | Per connection | | |
   | |              |  | | | | handler  | | callbacks      | | |
   | |              |  | | | |          <------            | | |
   | |  Handler <------------->         | |                | | |
   | |              |  + | | |      ------->               | | |
   | |              |    | | |          | |                | | |
   | |              |    + | +----------+ +----------------+ | |
   | +--------------+      +---------------------------------+ |
   +-----------------------------------------------------------+
~~~

The architecture diagram above describes the a typical multithread
scenario. Each network thread manages a separate picoquic stack,
and interfaces with the application with two types of callbacks:

- wake up callbacks, which can be triggered by the thread wake up API
- connection callbacks, which are triggered by connection events such
  as data arrival.

The application should keep track of the QUIC connections. When it
want to issue a call to a picoquic API, it can do it from within a
callback, for example when receiving data. It can also trigger the 
callback by waking up the stack. For example, if the application
has a message to send on a connection identified as `cnx`, it
should:

1. In the application thread:
    - Identify the thread associated with the connection, and find
   the associated thread context (noted `thread_ctx` here),
    - Wake up the thread associated with the connection, calling:
```
        ret = picoquic_wake_up_network_thread(thread_ctx);
```
2. In the wake up call back for the selected thread:
    - Mark the connection as ready to send a message on the selected stream:
```
        ret - picoquic_mark_active_stream(cnx, stream_id, 1, (void*)stream_ctx);
```
3. In the picoquic call back `picoquic_callback_prepare_to_send`
    - copy the parts of the message that have not yet been sent
      in the buffer returned by the call to `picoquic_provide_stream_data_buffer`
 
Calls to create new connection, or change the state of a connection, will
follow a similar pattern.

### Debugging the API usage

The rule for using the picoquic API is hopefully clear, but mistakes happen.
For example, the application might call an API like `picoquic_create_cnx`
or `picoquic_add_to_stream` directly from the main thread, or possibly
from a callback issued for another connection in a different thread.
For example, we can imagine "relay" style application
receiving data on a connection, and immediately queuing that
data on a different connection. The first call is executed on
the first connection's thread, but the second connection cannot
be accessed safely in that thread. Another thread might be
accessing the connection at the same time, risking a race
condition.

Race conditions are a pain to debug. The developer is faced with
random errors that are often very hard to understand. The program
may continue to execute for some time, until the corrupted state
causes a visible error or a crash. At that point, the developer has
a difficult task that requires analyzing logs and memory states, and
trying to reproduce a variety of hypotheses.

To debug these issues, picoquic has the compile option
`PICOQUIC_WITH_THREAD_CHECK`, which can be instantiated with
the `cmake` option `WITH_THREAD_CHECK=ON`. If picoquic is compiled
with that option, all API's defined in `picoquic.h` will check that
they are executing in the proper thread, and if not will execute
a `debugbreak()`, allowing the developer to quickly locate
and correct the threading issue. Instead of a hard-to-debug error, the
API will fail in an obvious way if it is not executed within the context of the
application thread.

This debug option is clearly not meant to be used in production. The
intent is to use it when trying to reproduce a bug, or possibly when
running a test suite.

# Further work

In the current stage of development, the support for multiple threads is
basic. It relies on the use of shared UDP ports, and the use of preferred
address migration. The support for session resume tickets and
connection tokens is minimal.

## Managing tokens and tickets

In QUIC, tokens and session resumption tickets are used to speed up the
establishment of new sessions. They are created by the server, passed to
the client over a connection, and used by the client to start a new connection.
If we have multiple servers, we must assume that the server processing the
new connection is not the same as the server that created the token or the ticket.
We can manage that using a Session Ticket Encryption key (STEK) shared by all
servers in the cluster, but we have to be concerned with potential attacks
in which the same token or ticket is used multiple times. We also need to
be concerned with management of tokens and tickets for clients.

In the current state of multithreading, we use a simple solution: the encryption
key for tickets and tokens is read from the "config" structure. If the
application does not set that key, the stack generates a random key that
is shared by all threads in the process. This allows picoquic to support
the basic functions like session resume and 0-RTT, with the following
limitations:

- if the deployment uses multiple processes or multiple servers
  sharing the same UDP port, it needs to use the same key in all processes and servers,
  which means that the key needs to be set in the "config" structure.
- The same key will be used for the duration of the process.
- The stack only keeps trace of used tokens or tickets in the context of a single thread,
  which means that the same token can be used once per thread, process and server.

The current code is designed for multithreaded servers. It can be used for clients,
but tickets and tokens are only remembered in the context of a thread. The session
resume and 0-RTT functions will only work if the application always call a given
server from the same thread.

There are many potential way to improve this. We could expose an API that the
application could use to reset the ticket encryption key in each thread. We could
provide some kind of management interface so an administrator can provide the
new key to multiple application. We could design a centralized service that keeps
track of used tokens and tickets. All that is for further study.

## Future work: Sharing the UDP port, with CID and EBPF

We need to use "preferred address" migration if assignment of
sockets to connections is based on hashes of addresses and ports:
the hash buckets may change over time, which could lead to
connection failures. The preferred address migration would not
be needed if the routing of connection to sockets was based
on Connection ID, and if the connection ID somehow encoded
the specific server in charge of the connection.

The QUIC 
[load balancing draft](https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers)
solves a related problem, the routing of packets to the "right" server in
a server farm. It does so by structuring and then encrypting the CID.
The logical structure of the CID is:

~~~
QUIC-LB Connection ID {
    First Octet (8),
    Plaintext Block (40..152),
}
Plaintext Block {
    Server ID (8..),
    Nonce (32..),
}
~~~

The first octet contains 1 bit identifying the current encryption key,
and then a few bits for the length of the server ID. The load balancer
decrypts the CID in incoming packets, retrieves the server ID, and route
the packets to that server.

If servers have multiple threads or multiple processes, we will need to
extend the server ID to identify not just the specific server, but
also the specific socket on that server. We will then associate an
EBNF script with the shared port using the socket option
SO_ATTACH_REUSEPORT_EBPF. The script will have to decode the incoming
CID, retrieve the socket identifier, and route the packet to
that specific socket. 

This is not yet implemented.

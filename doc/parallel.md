# Running picoquic on multiple threads in parallel

Picoquic was designed as a singled threaded module, with the assumption that
deployments requiring higher performance would simply run multiple instances
of picoquic in multiple parallel processes. But just saying that does not
mean that developers would not keep wondering why, for example,
they cannot have more than one network thread within a picoquic instance.
Why could not the application just say "create 15 network threads" instead
of "create just one"? Deployments would be easier if picoquic could manage
all the complexity of handling load balancing between multiple threads,
instead of leaving that to each application.

The first step with any big question like that is to document the issue
and explore possible solutions. That's what this document does. Or attempts to do.


# Parallelism by connection

The simplest design is to handle paraellism at the "connection" level.
The connection object (`picoquic_cnx_t`) and the related path object
(`picoquic_path_t`) hold much of the state variables enabling the
handling of the connection.

We briefly considered a "pipeline" option, in which CPU intensive functions
like send and receive packets or perform crypto would be delegated to a set of
of threads, while the "main" object would be single threaded. The pipeline option
would have some advantages, like guaranteeing that the application level API do
not change, or enabling high performance even if the system is only handling
a small number of connections. One downside is that the "main" thread would
become a bottleneck, but we could worry later about parallelizing that thread.
However, the remaining downside is that this is effectively "packet level"
parallelism, requiring context switching or message passing for each packet.
These context switchings can easily negate any potential performance
gain in the architecture.

We also considered parallelism at lower levels, such as "paths" or "streams",
but handling paths, streams or connections in different streams would create
contentions on the connection context, and require some systems of locks
that could also easily negate the performance gains.

In what follows, we will consier three forms of parallelism: multiple threads
in a single process, multiple processes, and multiple hosts.

## One process, multiple threads

~~~
              +----------------+
              | Application    |
              +----------------+
                  ^  ^  ^
                  |  |  | API
                  |  |  |
              +---v--|--|----------+
              |  +---v--|-------------+
  Network     |  |  +---v----------------+
  threads     |  |  |  Connection states |
              +--|  |    Shared UDP port +----> packets out
                 +--|                    +<---- packets in
                    +--------------------+
~~~

The basic architecture would be to have multiple network threads. Each network
threads manages a set of connections, and holds the "connection contexts" for
these connections. All these connections access a "shared socket".


## Multiple processes

This paper is focused on parallelism between threads in a single process.
We know of existing deployments that instead use parallelism between
multiple processes.


~~~
              +--------------------------------+
              |             +-----------------+|
              | Application | Network loop    ||
     +------->|             | Shared UDP port +----> packets out 
     |        |             |                 +<---- packets in
     |        |             +-----------------+|
     |        +--------------------------------+
     |        ...
     |        ...
     |        ...
     |        +--------------------------------+
     |        |             +-----------------+|
     |     +->| Application | Network loop    ||
     |     |  |             | Shared UDP port +----> packets out
     |     |  |             |                 +<---- packets in
     |     |  |             +-----------------+|
     |     |  +--------------------------------+
     v     v
 +---------------+
 | Coordinating  |
 | process       |      
 +---------------+
~~~

Each of the processes includes a "network loop" and its own application
code. These processes share a single port, such as all listening and sending
on UDP port 443. If applications need to share data or otherwise
synchronize, they will typically exchange messages with a coordinating
process.

In the most simple cases, such as a static web server, the application
will just read and write data from and to local storage, the need for
coordination is minimal, and the architecture works very well.
In more complex cases, the processes will need to share much more information,
often going through a "back end" service that manages the data base.

The "multi thread" architecture allows these coordination to happen
within a single process, allowing for example access to shared memory.
This may be more efficient in applications like a "media over QUIC"
relay, in which multiple threads share and dynamically update a
"media cache".

## Multiple Hosts

Both the thread level and process level parallelism are single CPU
solutions. Host CPUs are often multicore. The goal is to create as
many threads or as many processes as available cores on the CPU,
so as to fully use the CPU's resource. If the application demands
more resource than what a single CPU can provide, we will need to
consider load balancing across multiple hosts.

In these solutions, a load balancer is typically used to direct
incoming packets to the relevant server, or possibly to the
relevant process on a server. Many load balancers operate
at the UDP level, assigning incoming packets to a specific
server based on a hash of the IP and UDP headers. QUIC aware
load balancers assign packets to servers based on the Destination
CID field of the header. An example of such specification
can be found in the
[QUIC LB draft](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/).

# Sharing the UDP port

The deployments assume that external peers see a single system,
a single combination of IP address and UDP port. Whether the
system uses multiple threads, multiple processes or multiple
hosts, we end up with the same problem: select a host, a process
or a thread to handle the UDP connection, and making sure that
all packets used by that connection are processed by the
same thread.

## Using SO_REUSEPORT

The simplest way to share a UDP port in Linux is to use
the socket option "SO_REUSEPORT", which the manual describes as:

- SO_REUSEPORT (since Linux 3.9)

    Permits multiple AF_INET or AF_INET6 sockets to be bound to
    an identical socket address.  This option must be set on
    each socket (including the first socket) prior to calling
    bind(2) on the socket.  To prevent port hijacking, all of
    the processes binding to the same address must have the
    same effective UID.  This option can be employed with both
    TCP and UDP sockets.

    ...

    For UDP sockets, the use of this option can provide better
    distribution of incoming datagrams to multiple processes
    (or threads) as compared to the traditional technique of
    having multiple processes compete to receive datagrams on
    the same socket.

The default behavior of the Linux stack is to distribute packets to
sockets in the group using a 4-tuple hash. This would work for
basic QUIC connections in which the local host is the server, as long
as they are not using path migration or multipath, which could be
enforced by using the `disable_migration` transport parameter.

There is an issue with connections started by the local host as a client,
because the 4-tuple hash
of the outgoing UDP header will not always match the socket number
associated with the thread or process starting the connection. The
simple solution is to use a separate socket for starting client connections,
with each thread or process using a separate random port.

## Sharing the UDP port, with EBPF

If we want to support either connection migration or multipath,
we need to use a BPF or EBPF script.

- SO_ATTACH_REUSEPORT_CBPF
- SO_ATTACH_REUSEPORT_EBPF

    For use with the SO_REUSEPORT option, these options allow
    the user to set a classic BPF (SO_ATTACH_REUSEPORT_CBPF) or
    an extended BPF (SO_ATTACH_REUSEPORT_EBPF) program which
    defines how packets are assigned to the sockets in the
    reuseport group (that is, all sockets which have
    SO_REUSEPORT set and are using the same local address to
    receive packets).

    The BPF program must return an index between 0 and N-1
    representing the socket which should receive the packet
    (where N is the number of sockets in the group).  If the
    BPF program returns an invalid index, socket selection will
    fall back to the plain SO_REUSEPORT mechanism.

    Sockets are numbered in the order in which they are added
    to the group (that is, the order of bind(2) calls for UDP
    sockets or the order of listen(2) calls for TCP sockets).
    New sockets added to a reuseport group will inherit the BPF
    program.  When a socket is removed from a reuseport group
    (via close(2)), the last socket in the group will be moved
    into the closed socket's position.

    These options may be set repeatedly at any time on any
    socket in the group to replace the current BPF program used
    by all sockets in the group.

    SO_ATTACH_REUSEPORT_CBPF takes the same argument type as
    SO_ATTACH_FILTER and SO_ATTACH_REUSEPORT_EBPF takes the
    same argument type as SO_ATTACH_BPF.

    UDP support for this feature is available since Linux 4.5;
    TCP support is available since Linux 4.6.

Using EBPF, we could parse the destination CID of the incoming packet,
and return the corresponding socket number. Path migration and multipath
can be supported, as long as each of the processes or threads using
the port number generates CID that can be properly parsed by the
EBPF script.

With EBPF, the same socket can be use for QUIC connections accepted by the
local host as a server and for QUIC connections started by the local
host as a client, as long as all connections use the CID that match the
local socket.

## Parsing the CID

In the EBPF solution, the script needs to parse the CID to extract the
"thread number", or in the case of process parallelism the process
number. This is the same issue encountered by load balancers in
host parallelism deployments. We will asssume that the CID will
be compatible with the format specified by the
[QUIC LB draft](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/):

| First Octet | Server ID | Nonce          |
|-------------|-----------|----------------|

In that format, the Server ID identifies the server in multi-host
deployment. The nonce is set by the server, and must be
different for all CID issued by that server. We will need to
complement that format as:

| First Octet | Server ID | Thread ID | Nonce |
|-------------|-----------|-----------|-------|

EBPF script must return a socket ID, defined by the order in which the sockets
are created. We will use need to ensure that EBPF socket ID matches the
Thread ID. The length of the server ID and thread ID are deployment parameters.
For single-server deployments, we may omit the Server ID.

The QUIC LB draft supports encryption, the format being:

~~~
+-------------+------------------------------------+
| First Octet | Encrypted bits                     |
|             | +-----------+-----------+--------+ |
|             | | Server ID | Thread ID | Nonce  | |
|             | +-----------+-----------+--------+ |
+-------------+------------------------------------+
~~~

The first octet is defined as:

~~~
   First Octet {
     Config Rotation (3),
     CID Len or Random Bits (5),
   }
~~~

## Long term sharing and preferred address

The classic load sharing relies on anycast routing or hash based load balancing.
Both keep the routing stable enough in the short term, but are known to change
over time. Hash based load balancing buckets get redefined to better balance the
load, anycast routing changes as the network topology evolve. QUIC has a
solution: the server can indicate a "preferred address" during the connection
handshake, and the client can migrate the connection to that address once
the handshake completes.

We could certainly support the preferred address mechanism in the picoquic
socket loop. The network thread would need to open two sockets: one
for the shared UDP port, and one for an instance specific connection.
This will ensure that the connection survices any change in balancing
or routing.

Preferred address migration has a downside. It introduces overhead, and
possibly some additional delays at the beginning of the connection. This
is mostly an issue if the traffic is made of many very short connections,
as for example in a simple web server. It is much less of an issue
if the connections last a long time, as for example media over QUIC.

We noticed that if the QUIC instance manages both incoming "server"
connection and outgoing "client" connection, having an instance-specific
socket helps manage the client connections. Once we have made the design
choice of supporting outgoing connections, it makes sense to also
support preferred address migration for the server connections.

### Preferred address migration and firewalls

Preferred address migration looks attractive, but we have to be concerned
with firewall rules. Servers may well be located behind firewalls.
AWS deployments, for example, require that port
numbers be explicitly open in the firewall. We could imagine opening a
range of port numbers, but then we would need to ensure that the
nework threads use port numbers in that range.

# API discussion

The previous part of this document discussed network connectivity issues,
ensuring that the UDP packets can be routed to the appropriate server process
or server thread. We also have an API issue. The current architecture assumes
that the application interacts with exactly one network thread. The current model
assumes that all picoquic API are used within the context of this
network thread.

~~~
   +-----------------------------------------------------------+
   | +--------------+      +---------------------------------+ |
   | | application  |      | Network thread                  | |
   | |  thread(s)   |      |                                 | |
   | |  wake-up  ----------->       Wait loop                | |
   | |  function    |      |            |                    | |
   | |              |      |       +----+-----+ packets,     | |
   | |              |      |       |          | timers       | |
   | |              |      | +-----v----+ +---v------------+ | |
   | |  Handler <-------------> Wake up | | Picoquic stack | | |
   | |              |      | | callback | |                | | |
   | |              |      | |     ------->                | | |
   | |              |      | +----------+ |                | | |
   | |              |      | +----------+ |                | | |
   | |              |      | | Callback | | Per connection | | |
   | |              |      | | handler  | | callbacks      | | |
   | |              |      | |          <------            | | |
   | |  Handler <------------->         | |                | | |
   | |              |      | |      ------->               | | |
   | |              |      | |          | |                | | |
   | |              |      | +----------+ +----------------+ | |
   | +--------------+      +---------------------------------+ |
   +-----------------------------------------------------------+
~~~

In this model, the application thread does not directly call the 
picoquic APIs, except possibly during the thread initialization phase.
Once the thread are initialized, it waits for timers or external
events. 

The application thread(s) can call the wake up function,
for example if it wants to send data or create a
new connection, in which case the network thread stops waiting
and performs a wakeup callback. Within that call back,
the application can call picoquic APIs such as create a connection,
close a connection, or mark a stream ready for writing. It
will do that based on instructions provided by the application
thread.

The picoquic stack will also issue "per connection" callbacks
on when new connection are created, when data is received,
when the stack is ready to send "just in time" data, or when
other connection events occur. The application provides a
handler for those callback events. The handler code executes
in the context of the network thread and can call picoquic
APIs. Implementations will need to implement code to
safely exchange data between the network thread and the
application thread.

That model works well as long as the process handles a single
network thread, including in "parallel process" scenarios,
but it breaks if the application uses multiple network threads.

## Handling multiple threads

If a connection context
is tied to a thread, the picoquic APIs that operate on the connection
should be executed in that thread. 

~~~
   +-----------------------------------------------------------+
   |                   +---------------------------------+     |
   |                   | +---------------------------------+   |
   | +--------------+  | | +---------------------------------+ |
   | | application  |  | | | Network thread                  | |
   | |  thread(s)   |  | | |                                 | |
   | |  wake-up  ?--------->       Wait loop                | |
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

Suppose for example the application needs to create a new connection.
It will need first to select the network thread in which it wants to
create the connection, and wake up that specific thread. If it wants
to mark a stream as "ready to send", it should wake up the thread
that handles the corresponding connection. When that
thread executes the wake up call back, the callback code will need
to find out what the application intended to do on that thread,
and then perform the command. The main requirement is that the
application be "thread aware", which at a minimum requires
using thread-specific wake up calls, and also knowing which connection
executes on what thread.

The handling of connection callbacks does not need to change much.
When a callback is received, the callback handler will interact
with the application to provide data that was received, or get
data to send, or signal connection events -- pretty much in the
same way as if there was just one network thread. However,
there is still a risk of confusion if the logical response
to a call back on one connection involves a different connection.

## Isolating connections from each other

The design rule for so far for picoquic was that the picoquic
API should only be used in the context of "the" network thread.
If we handle multiple network threads, we need to be much more
specific: an API that changes the state of a connection should
only be used in the context of the specific network
thread that affects the connection.

For example, we can imagine "relay" style application
receiving data on a connection, and immediately queuing that
data on a different connection. The first call is executed on
the first connection's thread, but the second connection cannot
be accessed safely in that thread. Another thread might be
accessing the connection at the same time, risking a race
condition. 

Race conditions are a pain to debug. The developer is faced with
random errors that are typically very hard to debug.
It is much more reliable to prevent these errors, having the
API fail if it is not executed within the context of the
application thread.

The typical solution would be to
call an API like `gettid(2)` on Linux, compare it to the
thread ID of the connection, and react if the two do not match.
We may discuss whether this should be performed all the time,
or merely in debug mode. In debug mode, the reaction can be to
just trigger a breakpoint. If that breakpoint breaks during test,
the developer can examine the stack, find the offending code
line, and correct it. If the tests have good coverage, the
application will soon reach the desired quality level.

# Looking at the context variables

Should we have a QUIC context per thread, or a common QUIC
context for all threads?

Having a QUIC context per thread will probably work, but the threads
must all have access to the same keys. There may be issues with some
functions, like those ensuring on a server that session resume ticket
are used only once. We need more discussion there.

# TODO list

To implement the "basic UDP port sharing", we need:

1- Manage a thread ID and a corresponding socket ID

2- Add a "per thread" socket in the socket loop, to use either
   for "client mode connection" or for "preferred address"
   migration

3- Server side support of the "preferred address migration"

4- Use a CID generation function that includes the thread ID,
   so threads can generate CIDs without risk of collision.

To make the UDP port sharing more robust, we need:

5- Develop an EBPF script to direct packets to the right socket

If we want to use multiple network thread, we need to:

6- Add a pointer `picoquic_network_thread_ctx_t *` to the
   connection context to tie a connection to a thread

7- Possibly, add a `connection thread wakeup` API to ease
   application development

8- Document the thread ID in the wake up callback

9- Add a `THREAD_DEBUG` mode to detect misuse of the per
   connection API

10- Finish the study of which parts of `picoquic_quic_t`
   should remain in a per thread context and which would
   need to move to a global context










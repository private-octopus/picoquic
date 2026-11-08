# Memory management

Picoquic was initially designed for performance, with a choice to allocate
as much memory as necessary for maximal use of network resource. This
is a fine strategy in many cases, but it breaks when the supporting device
as limited resource. For example, we see
[deployment issues](https://github.com/private-octopus/picoquic/issues/1499)
with the application allocating hundreds of megabytes to ongoing connections
when doing connections at gigabit per seconds, which is a problem if the
supporting device has limited resource. The memory allocation on the
sender is largely a function of the bandwidth-delay product (BDP), but
occurrence of packet losses can increase the requirements. The situation is
different on senders and receivers. The current version provides 2 APIs
to manage memory usage per connection at the sender and the receiver:
`picoquic_set_cwin_max` and `picoquic_set_max_data_control`.

## Sender side memory use and management

The sender consumes memory for a variety of tasks, but in common applications
the bulk of the memory is used for packet management. The life of a packet
goes through a series of steps:

* when ready to send, the code prepares an empty packet, then tries to fill it
  with a variety of frames, such as acknowledgement, stream data, or various
  control frames.
* if there is nothing to send, the packet memory is released. Otherwise,
  an encrypted version of the packet is passed to the network for
  transmission, and the clear text version is kept in a queue of packets
  waiting for acknowledgement.
* if a timely acknowledgement is received, the frames in the packet are
  marked as processed. For example, if the packet contained stream data,
  the corresponding bytes are marked as received. The code updates
  RTT measurements and congestion control state, and the packet memory
  is released.
* If the packet is not acknowledged in time, it is marked lost. The frames
  in the packet are extracted and if necessary queued for transmission. If
  the packet contained data frames, it is queued for data frame retransmission.
  Then, the packet is moved to the "loss confirmation" queue. (The packet may
  be present in both the stream data retransmission and the loss confirmation
  queue, but it is not duplicated.)
* In some cases, the acknowledgement of a packet arrives late, after
  it was considered lost. If the packet is in the "loss confirmation"
  queue, the frames in the packet are examined and marked as received,
  RTT and congestion control state are updated. Then, the packet memory
  is released.
* When the code finally decides that no acknowledgement will arrive, and
  the stream frame have been repeated in other packets, the
  packet memory is released.

If the packet loss rate is small, the bulk of the memory is dedicated to
the list of packets that have been sent and are neither acknowledged or
declared lost. These packets are considered "in transit", and the size of
the data in transit is limited by the congestion window.

If many packets are lost, we will see many packets in the "loss confirmation"
queue. We will also see packets stay in the "not yet acknowledged"
queue until they are declared lost. This will tend to increase the memory
used by these two queues. 

The value of the congestion window is determined by the selected congestion
control algorithm, such as for example Cubic or BBR. In general that's fine,
but there can be bugs or unforeseen circumstances causing the window to become
really large. The solution is to set a cap to the maximum window size, so
that even if the congestion control is too optimistic, the memory size will
still be limited. The API to do that is:
~~~
void picoquic_set_cwin_max(picoquic_quic_t* quic, uint64_t cwin_max);
~~~
The cap will apply to all the connection managed in the specified QUIC context,
because all these connections share the same memory pool.

## Receiver side memory management

In normal circumstances, a QUIC receiver only need a small amount of memory
to receive packets, process them, and submit them to the application. But QUIC
guarantees that stream data will be delivered in sequence to the application,
which leads to "head of line blocking". In the worse case scenario, all data
is sent to a single stream. In case of packet loss, all data received on that
stream must be buffered until the loss is corrected, which typically requires
one round trip but might require two or more in the rare cases where the
repeated packet is itself lost, and maybe the repeat of that, etc.

QUIC includes flow control mechanisms so receivers can limit how many streams
the peer opens, how much data can be sent on individual streams, and how much
data can be sent on all the streams. By default, picoquic enforces the number
of streams limit, limit the number of concurrent streams that the peer can open
to the initial value set in the transport parameters `initial_max_stream_id_bidir`
or `initial_max_stream_id_unidir`. In contrast, picoquic by default automatically
increases the amount of data that can be sent per stream or globally, because
flow control tends to limit performance. This has a cost: if the peer sends
to much data, head of queue blocking can force the receiver to allocate
excessive amounts of memory.

Implementations that want to control that maximum amount of memory can use this API:
~~~
void picoquic_set_max_data_control(picoquic_quic_t* quic, uint64_t max_data);
~~~
Note that, per the QUIC protocol, endpoints that grant flow control credits cannot
withdraw them. If the application sets the maximum flow control limit upon
initialization, it will be applied to all connections. If the application sets
it after connections have started and have granted flow control credits, the
limit will only be applied once these credits have been consumed.

The memory allocated can exceed the flow control limit, because the memory
is allocated for each QUIC packet that the application receives. This was
done to avoid copying the data twice, once upon decrypting the packet, and
another when queuing the packet for later delivery on a stream. Instead,
the code keeps a copy of the received packet in memory until the stream data
has been delivered. If the peer sends packets in small data frames, the
amount of memory used will be significantly higher than the flow control
limit.

## Resisting fragmentation attacks

Picoquic nodes can receive out of order stream fragments due to the natural
process of packet loss and recovery. These fragments must be queued when awaiting
in order delivery. The "max stream data" and "max data" settings limit the
amount of memory used per stream or for the connection, but bad actors can try
to create memory usage in excess of these limits.

According to RFC 9000, stream data fragments are received in individual stream
frames, and can be received out of order. Picoquic stores each fragment in a
fixed size structure, regardless of its size. The fixed size structure is designed
to accommodate a maximum length segment, and the code is designed so that
such fragments can be created with zero copy. This increases performance
in normal conditions, but attackers can mount a fragmentation-reassembly
attack by deliberately sending small fragments, out of order. For example,
they could send one byte data frames at odd offsets, and never send the
hole filling data at even offsets.

Picoquic is designed to resist such attacks, but it has to use a loose heuristic
because small fragments may be naturally produced by some traffic patterns or
some loss recovery patterns. Picoquic will detect an attack and close the
connection if there are more than 128 fragments stored for a stream and
the memory required for these fragments is more than 6 times the
stream's flow control window counted from the last byte delivered to the
application, or if there are more than 128 fragments stored across all the
streams and the memory required for holding these fragments is larger than
6 times the connection's flow control window counted from the data
delivered to the application.

Applications can obtain the amount of memory used for reordering stream data
before delivery through the API:
```
size_t picoquic_get_reorder_queue_memory(picoquic_cnx_t* cnx);
```
## No global limit yet

In theory, we could devise an algorithm that automatically sets the sender or
receiver cap based
on the overall amount of memory available. For example, an algorithm could
monitor the total number of packets allocated across all connections,
lower the cap if the packets queue are too large, and progressively lift
it when conditions stabilize. But in practice this will require some work...

## Stream opening attacks

The reordering buffers discussed above are the main consumers of sender-side
memory, but the code also allocates memory for stream management. The stream
header itself is only a few hundred bytes, but some applications allocate
more memory for processing the stream content.

We see an example of "application level" per stream allocation with the
default HTTP3 server, "h3zero". It reads the size of the incoming frame from
the stream, and allocates as many bytes of memory to store it. The
maximum supported frame size is 64KB, and that memory will be freed once
the frame is parsed. That seems logical, but there is a potential
attack. An adversary could open lots of streams, send a few bytes on each
stream to announce a 64KB length, cause a 64KB allocation, and never complete
the stransmission of the frame. That will force the server to hold on
64KB of data for each stream, and that memory could be held until the
server decides to close the connection.

This attack can be mitigated by limiting the number of streams that the
pear can open, using the `initial_max_streams_bidi` and `initial_max_streams_uni`
transport pararameters during the connection setup. These two parameters
are set by default to 512, and the attacker can cause at most the allocation of 32MB per
connection. Limit it to 100, the lowest value authorized for HTTP/3 by
[RFC9114](https://www.rfc-editor.org/rfc/rfc9114.html) and the attacker
can only cause an allocation of 6.4MB of memory. This can be done
by calling the `picoquic_set_default_tp_value` to configure the QUIC context,
as in:

```
picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_streams_bidi, 512);
picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_streams_uni, 512);
```

Of course, limiting the number of streams has its downside. Some Web Transport
applications may well require supporting a large number of parallel streams,
and a limit of 100 streams may prove too constraining. It is also only a
partial solution: the attacker could just resort to opening many
connections.

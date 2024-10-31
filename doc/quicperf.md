# Performance testing with picoquicdemo

The picoquicdemo program supports multiple applications, one of which is "quic perf" defined by
Nick Banks in [this draft](https://datatracker.ietf.org/doc/draft-banks-quic-performance/). To
quote from the draft, _The QUIC performance protocol provides a simple, general-purpose
protocol for testing the performance characteristics of a QUIC
implementation._

To run the "perf" protocol and run a basic test scenario, do:
```
.\picoquicdemo -a perf test.privateoctopus.com 4433 "*1:0:-:397:5000000;"
```
Where `-a perf` means _set ALPN to "perf", and use the quicperf protocol to reach the server_
and the quoted argument describes a test scenario, in which:

*   *1 means repeat this once
*   0 means use stream 0
*   The hyphen `-` means start immediately (a number would mean, start when stream N download is complete)
*   397 means client will post 397 bytes
*   5000000 means server will send 5M bytes

The program can run multiple test scenarios in a single session, e.g.:
```
    "*1:0:-:397:5000;*1:4:0:432:4999;"
```
which will do one transaction on stream 0, then start another one on stream 4
once stream 0 completes.

When used as a client, the program will display statistics, e.g.:
```
Connection_duration_sec: 4.425348
Nb_transactions: 10000
Upload_bytes: 1000000
Download_bytes: 1000000
TPS: 2259.709293
Upload_Mbps: 1.807767
Download_Mbps: 1.807767
```
For more detailed statistics, or for gathering statistics on servers, `picoquicdemo`
can provide performance logs, see {{performance logs}}. 

There are lots of other arguments in `picoquicdemo`, but you probably don't need them for
running quicperf, although you may consider collecting quic logs using the `-q` option when
debugging. Also, the "-h"
option will produce a list of command line arguments.
```
    .\picoquicdemo -h
```
## Performance logs

When doing performance measurements, the natural instinct is to turn off all logging, because
writing logs slows down the program execution. On the other hand, it is very useful to have
at least some logging, in order to understand what changes from run to run, and what might
affected performance. The performance logs are designed to minimize the interference. The
data is written to disk at the end of the connection. If the performance test involves
multiple simultaneous connections, the server will keep the data in memory and write it to
disk when all connections are complete.

To produce the performance logs with `picoquicdemo`, use the argument `-F` as in:
```
.\picoquicdemo -k key.pem -c cert.pem -p 4433 -F server_log.csv
.\picoquicdemo -q client_log.csv -a perf test.privateoctopus.com 4433 "*1:0:-:397:5000000;"
```
The performance logs are formatted as CSV file, with the following columns:

* Log_v: Performance log version
* PQ_v: Picoquic version
* Duration: Time from start to finish, seconds
* Sent: Number of bytes sent
* Received: Number of bytes received
* Mpbs_S: Sending rate, Mbps
* Mbps_R: Receive rate, Mbps
* QUIC_v: QUIC version
* ALPN: ALPN
* CNX_ID: Initial connection ID (same for client and server)
* T64: Start time, in 64 bit format, in microseconds
* is_client: 1 if client, 0 if server
* pkt_recv: Number of packets received
* trains_s: Number of packet trains sent
* t_short: Number of packet trains shorter than target
* tb_cwin: Number of packet trains shorter because of CWIN
* tb_pacing: Number of packet trains shorter because of pacing
* tb_others: Number of packet trains shorter for other reasons
* pkt_sent: Number of packets sent
* retrans.: Number of packets retransmitted
* spurious: Number of spurious retransmissions
* delayed_ack_option: 1 if delayed ack negotiated, 0 otherwise
* min_ack_delay_remote: Minimum ack delay set by peer (microsecond)
* max_ack_delay_remote: Maximum ack delay set by peer (microsecond)
* max_ack_gap_remote: Maximum ack gap set by peer
* min_ack_delay_local: Minimum ack delay required from peer (microsecond)
* max_ack_delay_local: Maximum ack delay required from peer (microsecond)
* max_ack_gap_local: Maximum ack gap required from peer
* max_mtu_sent: Maximum sender MTU
* max_mtu_received: Largest packet received
* zero_rtt: 1 if zero rtt was negotiated
* srtt: Smoothed RTT at end of connection
* minrtt: Min RTT at end of connection
* cwin: Largest CWIN during connection
* ccalgo: Congestion control algorithm
* bwe_max: Largest bandwidth estimate (bytes per second)
* p_quantum: Largest pacing quantum
* p_rate: Largest pacing rate (bytes per second)

## Media Transport Extensions

Picoquic extends the QPERF specification to enable performance testing for
"Multimedia" applications, such as application based on "Media over QUIC"
transport. MoQ transport uses "media streams", which are sent over
a series of QUIC streams. Example of MoQ transport encoding could be:

* for a media composed of a series of independent frames, open a stream to send
  a new frame 30 or 60 times per second.
* send an audio stream as a series of QUIC datagrams, 50 times per seconds.
* send a video stream as a series of QUIC streams, each stream containing
  a large I frame followed 30 or 60 times per second by a P frame.

A typical client-server connection may have:

* a client sending an audio stream and three simultaneous video streams for 
  low, medium and high definition video,
* a server sending 12 sets of audio and video streams from remote clients.

The media transport sets different priorities to different QUIC streams, so
that in case of congestion the audio and low definition video streams are properly
received, while the higher definition video streams may be delayed. If a QUIC
stream carrying high definition video "falls behind" too much, it will be
reset; that video transmission will restart as a new stream after the next
I frame is available.

Our goal here is to test transport level performance, not audio and video
encodings. We may tolerate some small differences. For example, MoQ sends
media on unidirectional streams, but we find it easier to have the client
request media from the server on bidirectional streams, because that
let us entirely specify the test scenarios from the client.

The current syntax for quicperf scenario description is:
~~~
scenario = stream_description |  stream_description ';' *scenario

stream_description = ['*' repeat_count ':'] [ stream_number ':'] post_size ':' response_size
~~~
Where "[ xx ]" describes an optional element, "xx | yy" describes an alternative between xx and yy,
and  *xx describes any number of element xx, including zero.

To enable media testing, we change that description.
We allow two alternatives to "stream_description": "stream media" and "datagram media",
and, we add a stream_id to the description, to be used in reports. For all
streams, we can specify a "previous stream" to indicate that the
specified stream shall only start after all repetitions of this previous stream
are complete. For all streams, we may also specify a "priority", which should
be applied by both client and server.

The multimedia stream description starts with the letter "m" (media stream) or
'd' (datagram stream), followed by frequency expressed as the number of
frames per second, and indication of whether  then number of frames and frame size. 

When multiple
frames can be sent of the same stream, we add to the description
the number of frames per group, the size of the mark data sent by the client,
the size of the mark response from the server, and the delay for
noticing that the stream has fallen behind and should be reset.

The formal syntax becomes:
~~~
scenario = stream_choice |  stream_choice ';' *scenario

id = alphanumeric-string | '-'
previous-stream-id = alphanumeric-string

stream_choice = [ '=' id [':' previous-stream-id ':' ]]['*' repeat_count ':']
                [ ':' 'p' priority ] { stream_description | media_stream | datagram_stream }

stream_description = post_size ':' response_size

media_stream = stream_media_description | datagram_media_description

stream_media_description = 'm' media_description

datagram_media_description = 'd' media_description

media_description = frequency  ':' [ 'n' nb_frames ':' ] [ client_or_server ':' ] frame_size ':' 
              [ group_description ':' ] [ first_frame ':'] [ reset_delay ':' ]

client_or_server = 'C' | 'S'

group_description = 'G' frames_per_group

first_frame = ['I' first_frame_size ]

reset_delay = ['D' reset_delay_in_ms ]

~~~
The modified QPERF program produces a report as a CSV file, with one line per "frame" -- a post/response
or a mark/response. The columns in the CSV file are:

* id: the alphanumerical "id" field in the scenario specification,
* stream_type: 's' or 'd' for stream or datagram,
* repeat_number: the repetition number of this stream,
* mark_count: the number of the `mark`, or zero if this is the first frame on the stream.
* send_time: in microseconds from the beginning of the test.
* nb_bytes_send: number of bytes sent, which should be either `post_size` or `mark_size`,
* recv_time: time at which the last byte of the `post` or `mark` was received,
* nb_bytes_recv: number of bytes received, which should be either `post_size` or `mark_size`,
* is_reset: 1 if the stream was reset at this point, 0 otherwise.

### Extended PERF protocol

The standard Perf protocol uses bidirectional streams in a very simple way: the client
opens a stream and starts sending data; the server reads the number of required bytes in
the first 8 bytes of the client stream, and sends that many bytes to the client. We extend
this protocol by using unidirectional streams and datagrams.

Both the client and the server may start unidirectional streams. The first byte of
the stream indicates the type of the stream:

* 0x01: client control stream
* 0x02: data stream, from client or server.
* 0x03: server report stream

The client control stream carries a set of commands from the client. Each
command instructs the server to a specific media stream, and is encoded as:

~~~
media_stream_command {
   command_length(8),
   media_stream_id (i),
   priority (8),
   media_type (i),
   frequency (i),
   number_of_frames (i),
   frame_size (i),
   frames_per_group (i),
   first_frame_size (i)
}
~~~
The `media stream id` is a number chosen by the client to uniquely
identify the media stream. The media type is set to either
stream (0) or datagram (1). the other parameters are copied from
the scenario description of the media stream.

In response to these commands, the server initiates either a series of
unidirectional streams (media type 0) or series of datagrams (media type 1).

A media stream is sent as a series of unidirectional streams.
The unidirectional streams contain a series of frames. Each stream starts
by a stream type mark (0x02) followed by a stream header:

~~~
media_stream_header {
   header_length(8),
   media_stream_id (i),
   group_id (i)
}
~~~

The header is followed by a series of frames:
~~~
media_stream_frame {
   header_length(8),
   sender_time_stamp(i),
   frame_length(i),
   frame_bytes(..)
}
~~~

Each unidirectional stream sent in response to a command contains the number
of frames specified by the `group_size` parameter, except for the last stream
in the series, which will contain exactly the number of frames required
so the total number sent across all streams for this command equals
`number_of_frames`. The first frame will have the size specified in the
`first_frame_size` parameter, the other frames the size specified by the
`frame_size` parameter. The server generates the frames progressively,
according to the `frequency` parameter.

Datagram streams are sent as series of datagrams. The content of each
datagram is set as:
~~~
media_datagram_header {
   media_stream_id (i),
   group_id (i),
   frame_id (i),
   sender_time_stamp (i),
   datagram_bytes (..)
}
~~~
The client may also send unidirectional streams and datagrams. The server receives
these streams and for each frame sends a report on the server response
stream:
~~~
media_stream_report {
   header_length(8),
   media_stream_id (i),
   group_id (i),
   frame_id (i),
   client_time_stamp (i),
   server_time_stamp (i)
}
~~~

Frames and datagrams carry a `sender_time_stamp`, set at the local time at which
the server or the client created the frame, expressed in microseconds since
the beginning of the connection. In server reports, the `client_time_stamp`
carries a copy of the `sender_time_stamp` in the frame or datagram,
and the `server_time_stamp` indicates the time at which the frame or
datagram was received by the server.

The client may issue a `stop sending` request for a specific unidirectional
stream. Upon receiving the request, the server will reset the stream. The
server will not send the frames that may remain in the group. It will start
the next group at the "expected" time, as if all the previous frames had been
sent.

The client opens exactly one control stream, and closes it when it has no
more requests to send and no more response to expect. Opening more than
1 control stream is a protocol error.

The server will open exactly 1 response stream. Opening more than
1 response stream is a protocol error. The server will close
that stream when all required reports have been sent and the client has
closed the control stream.
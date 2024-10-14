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
and, we add a stream_id to the description, to be used in reports.
The multimedia stream description starts with the letter "m" (media stream) or
'd' (datagram stream), followed by priority, a specification of the number of
frames per second, post and response size. When multiple
frames can be sent of the same stream, we add to the description
the number of marks, the size of the mark data sent by the client,
the size of the mark response from the server, and the delay for
noticing that the stream has fallen behind and should be reset.

The formal syntax becomes:
~~~
scenario = stream_choice |  stream_choice ';' *scenario

id = alphanumeric-string

stream_choice = [ '=' id ':' ]['*' repeat_count ':'] { stream_description | media_stream | datagram_stream }

stream_description = [ stream_number ':'] post_size ':' response_size


media_stream = stream_media_description | datagram_media_description

stream_media_description = 's' media_description

datagram_media_description = 'd' media_description

media_description = priority ':' period ':' post_size ':' response_size
                    [ ':' nb_marks ':'  marks_size ':' mark_response_size ':' reset_delay ]
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

We also modify the "on the wire" format of the PERF protocol. According to
[the](https://datatracker.ietf.org/doc/draft-banks-quic-performance/),
_Every stream opened by the client uses the first 8 bytes of the
stream data to encode a 64-bit unsigned integer in network byte order
to indicate the length of data the client wishes the server to
respond with_. We changed that as follow:

* If the first byte is lower than 0xFF, the first 8 bytes encode the desired length of the server response.
* If the first byte is set to 0xFF, the first 8 bytes encode a media stream specification, using the syntax:

~~~
media_stream_header {
   first_byte_mark (8) = 0xFF
   priority (8),
   post_size(24),
   response_size (24)
}
~~~
Once the server has received the media stream header and `post_size` bytes, it posts
the requested number of response bytes on the stream. The server may
find on the same stream either a FIN mark or the next media stream header,
corresponding to the next mark. It repeats the processing, until it encounters
the FIN mark for the stream.


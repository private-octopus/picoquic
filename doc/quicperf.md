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

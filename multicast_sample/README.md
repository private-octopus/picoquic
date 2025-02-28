picoquic multicast
===============

The multicast program is a simple QUIC client/server demo.

Building
--------
picoquic\_multicast is built as part of the compilation process of picoquic. It
will be available in the root folder.

Usage
-----
Usage:

```bash
../picoquic_multicast client server_name port folder *queried_file
```

or :  

```bash
../picoquic_multicast server port cert_file private_key_file folder
```

Example
-------

Generate the certificates:

```bash
openssl req -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem
```

These commands will prompt a few questions, you don't need to put actual data
for this simple test.

Create a folder to hold server files:

```bash
mkdir server_files
echo "Hello world!" >> ./server_files/index.htm
```
And run the server:

```bash
./picoquic_multicast server 4433 ./ca-cert.pem ./server-key.pem ./server_files
```
Then, test if you can reach it using the client:

```bash
./picoquic_multicast client localhost 4433 /tmp index.htm
```

Getting logs
------------
Both server and clients will create logs of the connections if they can write files
in the expected folders. If you want logs, you will need to create these
folders before launching the server or the client.

The log files are in the [qlog format](https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/).
They will be added to the working directory of client or server. The name of the log files are derived from
the initial connection identifier used for the connection, which is represented
as a string of hexadecimal digits. For example, if the Initial CID is
`012345678abcdef`, the logs created by client and server will be:

```
012345678abcdef.client.qlog
012345678abcdef.server.qlog
```

The qlog syntax is defined using JSON. The logs can be read using a text editor,
or with specialized tools like [QVIS](https://qvis.edm.uhasselt.be/)

Building the multicast sample
-------------------
The multicast is built when building `picoquic` using `cmake` and `make`, but you
may want to build it separately from `picoquic`. For that, you can use the cmake 
target `multicast` and just execute `make multicast` instead of `make`.

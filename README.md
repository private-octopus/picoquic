# picoquic

Minimalist implementation of the QUIC protocol, as defined by the IETF.
The IETF spec started with the version of QUIC defined by Google and
implemented in Chrome, but the IETF spec is independent of Chrome, and
does not attempt to be backward compatible. The main developer is 
Christian Huitema.

The first goal of this project is to provide feedback on the development
of a QUIC standard in the IETF QUIC WG. Information on the WG is available at
https://datatracker.ietf.org/wg/quic/charter/. The in-progress version of
the spec is available on GitHub at https://github.com/quicwg.

The second goal is to experiment with API for non-HTTP development, such as
DNS over QUIC. Then there are plenty of other features we may dream off,
such as support for multipath, or support for peer-to-peer applications.
That's on the horizon, but not there now.

The code in this repo is a work in progress. In fact, the specification itself
is a work in progress. The working group is progressing by running a series
of meetings and of interop trials between several implementations, listed
at https://github.com/quicwg/base-drafts/wiki/Implementations. The current
interoperability matrix is listed at 
https://docs.google.com/spreadsheets/d/14Vw0EX8XG0YRKxSdcDxloBjOkTt9FpbJMpBAg1Hvbmc/edit#gid=0.

# Development

Picoquic is currently developed as a Visual Studio 2017 project,
and simultaneously tested on Windows and on Linux. It has a dependency
on the Picotls implementation of TLS 1.3 (https://github.com/h2o/picotls).
Picotls has two mode, a feature rich version that depends on OpenSSL, and a
leaner version that only depends on the "minicrypto" library. For now,
Picoquic uses the OpenSSL version, and has a dependency on OpenSSL.

The project consists of a core library (picoquic), of a test library
(picoquictest), and of a test program (picoquicfirst). All these are
written in C. In the Visual Studio project, the
test library is wrapped up in the Visual Studio unittest framework, which
makes for convenient regression testing during development. In the Linux
builds, the tests are run through a command line program.

# Milestones

The QUIC working group has defined a set of implementation milestones for
the successive interoperability tests. These are listed on the QUIC Wiki.

## First implementation draft

The first implementation draft 
(https://github.com/quicwg/base-drafts/wiki/First-Implementation)
required setting a connection and then tearing in down.
It was the basis for the interop tests performed during the IETF meeting 
in Prague in July 2017. Picoquic meets these requirements and has demonstrated
successful connection setup and teardown with mozquic (https://github.com/mcmanus/mozquic)
and with ngtcp2 (https://github.com/ngtcp2/ngtcp2).

## Second implementation draft

The next milestone was the second implementation draft
(https://github.com/quicwg/base-drafts/wiki/Second-Implementation-Draft).
It was used as the bais for interop tests in Seattle in October 2017.
Picoquic supports all of these features, including:

* Handshake
* Version Negotiation
* Stream Data (encrypted)
* Close
* HTTP/0.9 exchange
* server stateless retry
* stateless reset
* flow control

We demonstrated interop with a number of implementations, and also found a few bugs that
have been fixed -- see closed issues for details. 

## Further milestones

Of course, the second implementation draft is not the final one. 
The second interoperation draft is based on the draft-05 of the
QUIC spec: https://tools.ietf.org/html/draft-ietf-quic-transport-05.
Everybody expects that spec to evolve. 
The interop plan does not test every feature of the transport. The big missing
feature at the transport level is 0-RTT support. Picoquic will have that soon, but the interop tests
will probably have to wait until at least November 2017. After that, the big transport features will
be connection mobility and possibly multipath. But that will come later.

The interop plan is also punting on application mapping. The data transfers are using HTTP 0.9,
which is a fine test tool but not quite on par with HTTP 2.0. 
We don't know yet whether we will implement an HTTP2 mapping in Picoquic.
We might, but that's a lot of work. If someone is interested doing that and want
to collaborate, they are welcome. In parallel, we plan to do an implementation
of DNS over QUIC (https://datatracker.ietf.org/doc/draft-huitema-quic-dnsoquic/).

After October, we will start to spend time bettering the implementation. Until now 
the focus has been on correctness rather than performance. We will keep correctness,
but we will improve performance, especially in light of practical experience with 
applications. Suggestions are wellcome.

# Building Picoquic

Picoquic is developed in C, and can be built under Windows or Linux. Building the
project requires first managing the dependencies, Picotls (https://github.com/h2o/picotls)
and OpenSSL.

## Picoquic on Windows

To build Picoquic on Windows, you need to:

 * Install and build Openssl on your machine

 * Document the location of the Openssl install in the environment variable OPENSSLDIR

 * Clone and compile Picotls, using the Picotls for Windows options

 * Clone and compile Picoquic, using the Visual Studio 2017 solution picotls.sln included in 
   the sources.

 * You can use the unit tests included in the Visual Studio solution to verify the port.

## Picoquic on Linux

The build expereince on Linux is now much improved, thanks to check-ins from Deb Banerjee,
Igor Lubashev. 

To build Picoquic on Linux, you need to:

 * Install and build Openssl on your machine

 * Clone and compile Picotls, using cmake as explained in the Picotls documentation.

 * Clone and compile Picoquic:
~~~
   cmake .
   make
~~~
 * Run the test program "picoquic_ct" to verify the port.

## Picoquic on MacOSX

Thanks to Frederik Deweerdt for ensuring that Picoquic runs on MacOSX. The build steps
are the same as for Linux.

## Developing applications

Sorry, not all that much documentation yet. This will come as we populate the wiki. Your
best bet is to look at the demonstration program "picoquicdemo" that is included in the
release. The sources are in "picoquicfirst/picoquicdemo.c".
~~~

 




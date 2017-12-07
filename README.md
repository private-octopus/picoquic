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
https://docs.google.com/spreadsheets/d/1D0tW89vOoaScs3IY9RGC0UesWGAwE6xyLk0l4JtvTVg/edit#gid=273618597.

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
It was used as the basis for interop tests in Seattle in October 2017.
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

## Second and an half implementation draft

The interop test during the Singapore IETF were still based on the second
implementation draft.
The feature set and the tests remained the same, the emphasis being on actually
verifying that all these features work. This entailed documenting the tests that
should pass to claim interop on the various functions. The only change is that
the interop will be based on draft-07 instead of draft-05.

Just changing the draft number does not look like much, but the draft-07 brought in a
number of protocol changes:

* Change the protection of clear text packets to use AES-GCM instead of FNV-1A,
  with a version dependent key that prevents "dumb" firewalls from messing with
  the packet content.

* Removal of the option to send 1-RTT packets using the long header form.

* Change the ACK format to remove the timestamps. (They may be reintroduced later
  as a negotiated option.)

* Addition of an APPLICATION_CLOSE frame.

* Change of the format of the Stateless Reset packet.

* Change of the format of the CONNECTION_CLOSE and STOP_SENDING frames, with 
  the error code now being 16 bits instead of 32 bits.

These are all incompatible changes, and the developers had to
implement and test them before the IETF meeting in Singapore. All these changes are
now implemented in Picoquic, which supports the version 0xFF00007. We have managed
already to demonstrate interoperability with several implementations of draft-07,
such as nghttp2 and winquic.

## Third implementation draft

The next scheduled Interop will happen "on line", in December 2017. It will be based
on draft-08, which is not yet published. Based on the current editor copy,
we know that draft-08 will bring a number of changes, some of witch are very disruptive:

* Format changes of pretty much all frames, with a new variable length integer
  format replacing the multiple ad hoc compression schemes inherited from Google QUIC.

* Redefinition of the "stream ID", to allow both bidirectional and unidirectional
  streams.

* Redefinition of the "ping" frame to carry an optional payload that the peer should
  repeat in a "pong" frame.

* Tightening of the closing logic.

* Change of format of the QUIC header, with the version field moving in front of the
  sequence number.

All of these are already implemented in the test version of Picoquic. Next we need to compile with the TLD draft 22 version of PicoTLS, and fix the issues in the list. Two of those are "session resume and "0 RTT". These two may or may not be fixed by December 18.
The interop plan requires them, but it may be hard. Worst case, we will demonstrate them at
the next interop session in Melbourne in January. In any case, Interop tests have not yet begun. 

## Further milestones

Of course, even the draft-08 will not be the final one. 
Everybody expects that spec to still evolve. 
After that, the big transport features will
be connection mobility and possibly multipath. But that will come later.

The interop plan is also punting on application mapping. The data transfers are using 
HTTP 0.9, which is a fine test tool but not quite on par with HTTP 2.0. 
We don't know yet whether we will implement an HTTP2 mapping in Picoquic.
We might, but that's a lot of work. If someone is interested doing that and want
to collaborate, they are welcome. In parallel, we plan to do an implementation
of DNS over QUIC (https://datatracker.ietf.org/doc/draft-huitema-quic-dnsoquic/).

After December, we will start to spend time bettering the implementation. Until now 
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

The build experience on Linux is now much improved, thanks to check-ins from Deb Banerjee
and Igor Lubashev. 

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


 




# picoquic

Minimalist implementation of the QUIC protocol, as defined by the IETF.
The IETF spec started with the version of QUIC defined by Google and
implemented in Chrome, but the IETF spec is independent of Chrome, and
does not attempt to be backward compatible. 

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
https://docs.google.com/spreadsheets/d/1D0tW89vOoaScs3IY9RGC0UesWGAwE6xyLk0l4JtvTVg/edit#gid=0

# Development

Picoquic is currently developed as a Visual Studio 2017 project. It has a dependency
on the Picotls implementation of TLS 1.3 (https://github.com/h2o/picotls).
Picotls has two mode, a feature rich version that depends on OpenSSL, and a
leaner version that only depends on the "minicrypto" library. For now,
Picoquic uses the OpenSSL version, and has a dependency on OpenSSL.

The project consists of a core library (picoquic), of a test library
(picoquictest), and of a test program (picoquicfirst). All these are
written in C. In the Visual Studio project, the
test library is wrapped up in the Visual Studio unittest framework, which
makes for convenient regression testing during development.

The plan is to make Picoquic available on Linux as well as Windows. It is just a
simple matter of writing the appropriate make files, and that's something for
one of our next milestones.

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

The next milestone is the second implementation draft
(https://github.com/quicwg/base-drafts/wiki/Second-Implementation-Draft).
It will be used for the next interop test, in Seattle in October 2017.
Picoquic already supports several of these features, and plan to have them
all in time for the Seattle interop meeting.





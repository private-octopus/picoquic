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

The code in this repo is a work in progress, but it is getting stable, just
like the specification itself. The working group just issued draft-27, which
is meant as the stabilization draft. We may expect a few draft changes in the
next months, but these should not affect the wire format. At this stage the
changes in Picoquic will be mostly driven by performance issues, or API
improvements. And bug fixing, too.

There are many implementations of Quic, listed
at https://github.com/quicwg/base-drafts/wiki/Implementations. The interop
goals are defined at https://github.com/quicwg/base-drafts/wiki/17th-Implementation-Draft,
which points to the current interoperability matrix. Several implementations provide
docker images to the "Quic Interop Runner" project, with results updated daily
at https://interop.seemann.io/.

Bastian Köcher has developed bindings of the picoquic library to [RUST](https://www.rust-lang.org/en-US/). 
His repository can be found [here](https://github.com/bkchr/picoquic-rs).
You may want to check it.


# Development

Picoquic is currently developed as a Visual Studio 2017 project,
and simultaneously tested on Windows and on Linux. It has a dependency
on the [Picotls implementation of TLS 1.3](https://github.com/h2o/picotls).
Picotls has two modes, a feature rich version that depends on OpenSSL, and a
leaner version that only depends on the "minicrypto" library. For now,
Picoquic uses the OpenSSL version, and has a dependency on OpenSSL.

The project consists of a core library (picoquic), of a test library
(picoquictest), and of a test program (picoquicfirst). All these are
written in C. In the Visual Studio project, the
test library is wrapped up in the Visual Studio unittest framework, which
makes for convenient regression testing during development. In the Linux
builds, the tests are run through a command line program.

# Milestones

As explained in the Wiki, Picoquic is actively tested against other implementations
during the QUIC Interop days. See https://github.com/private-octopus/picoquic/wiki/QUIC-milestones-and-interop-testing.

The current version is aligned with draft 27. All big features are supported, including
the interface between QUIC and TLS, 0-RTT, migration and key rollover. The state of
development is tracked in the list of issues in this repository.

We have started an implementation
of [DNS over QUIC](https://datatracker.ietf.org/doc/draft-huitema-quic-dnsoquic/)
as [Quicdoq](https://github.com/private-octopus/quicdoq). DNS over Quic is interesting
by itself, but it also provides an example for building an application different than
HTTP on top of Picoquic.

We are spending time bettering the implementation. Until now 
the focus has been on correctness rather than performance. We will keep correctness,
but we will improve performance, especially in light of practical experience with 
applications. Suggestions are wellcome.

# Building Picoquic

Picoquic is developed in C, and can be built under Windows or Linux. Building the
project requires first managing the dependencies, [Picotls](https://github.com/h2o/picotls)
and OpenSSL. Please note that you will need a recent version of Picotls --
the Picotls API has eveolved recently to support the latest version of QUIC. The
current code is tested against the Picotls version of Fri May 8 15:47:16 2020 +0900,
after commit `5e0f82e184f1ae79de58837819b13ea7ef89b6f1`. The code uses OpenSSL
version 1.1.1.

## Picoquic on Windows

To build Picoquic on Windows, you need to:

 * Install and build Openssl on your machine

 * Document the location of the Openssl install in the environment variable OPENSSLDIR
   (OPENSSL64DIR for the x64 builds)

 * Make sure that a copy of `libcrypto.lib` is available at that location, and that
   a copy of `applink.c` is available at the `include` location: $(OPENSSLDIR)\include\
   for win32 builds, $(OPENSSL64DIR)\include\ for the x64 builds.

 * Clone and compile Picotls, using the Picotls for Windows options. The picotls project
   should be in the same directory level as the picoquic project, and the folder name 
   should be kept as  picotls.

 * Clone and compile Picoquic, using the Visual Studio 2017 solution picoquic.sln included in 
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
 * Run the test program `picoquic_ct` to verify the port.

## Picoquic on MacOSX

Thanks to Frederik Deweerdt for ensuring that Picoquic runs on MacOSX. The build steps
are the same as for Linux.

## Picoquic on FreeBSD

Same build steps as Linux. Picoquic probably also works on other BSD variants, but only FreeBSD
has been tested so far.

## Developing applications

Sorry, not all that much documentation yet. This will come as we populate the wiki. Your
best bet is to look at the demonstration program "picoquicdemo" that is included in the
release. The sources are in "picoquicfirst/picoquicdemo.c".

## Testing previous versions

The code is constantly updated to track the latest version of the specification. It currently
conforms to draft-28, and will negotiate support for the corresponding version `0xFF00001c`.
It will also accept negotiation of version `0xFF00001b`, draft-27. 

# Creating QLOG Log Files

See [How To Produce QLOG files with picoquic](doc/QLOG.md)

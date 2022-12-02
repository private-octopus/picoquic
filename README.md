# picoquic

Minimalist implementation of the QUIC protocol, as defined by the IETF.
The IETF spec started with the version of QUIC defined by Google and
implemented in Chrome, but the IETF spec is independent of Chrome, and
does not attempt to be backward compatible. The main developer is 
Christian Huitema.

The first goal of this project was to provide feedback on the development
of a QUIC standard in the IETF QUIC WG. Information on the WG is available at
https://datatracker.ietf.org/wg/quic/charter/. QUIC has been published as
RFC 9000, but there is still ongoing work, for example on multipath. Picoquic
enables developers to test this new work.

The second goal is to experiment with API for non-HTTP development, such as
DNS over QUIC -- see RFC 9250. Then there are plenty of other features we may dream off,
such as support for multipath, or support for peer-to-peer applications.
That's on the horizon, but not there now.

The code in this repo is stable, supporting the QUIC v1 and testing compliance.
It also includes support for a number of extensions. Performance work is
ongoing -- recent tests showed picoquic sending data at up to 5Gbps.

There are many implementations of Quic, listed
at https://github.com/quicwg/base-drafts/wiki/Implementations. Several implementations provide
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
(picoquictest), and of a test program (picoquicdemo). All these are
written in C. In the Visual Studio project, the
test library is wrapped up in the Visual Studio unittest framework, which
makes for convenient regression testing during development. In the Linux
builds, the tests are run through a command line program.

# Milestones

As explained in the Wiki, Picoquic is actively tested against other implementations
during the QUIC Interop days. See https://github.com/private-octopus/picoquic/wiki/QUIC-milestones-and-interop-testing.

The current version is aligned with version 1, [RFC 9000](https://datatracker.ietf.org/doc/rfc9000/).
All big features are supported, including
the interface between QUIC and TLS, 0-RTT, migration and key rollover. The state of
development is tracked in the list of issues in this repository. The code also
supports several features that are not yet standardized, including
[Datagrams](https://datatracker.ietf.org/doc/draft-ietf-quic-datagram/),
[ACK Frequency](https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/),
[Compatible Version Negotiation](https://datatracker.ietf.org/doc/draft-ietf-quic-version-negotiation/),
and [Multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/).
The code includes specific tuning for geostationary satellite links
and long delay links, including
support for the [BDP Frame Extension](https://datatracker.ietf.org/doc/draft-kuhn-quic-bdpframe-extension/).


An implemention of DNS over QUIC is available
as [Quicdoq](https://github.com/private-octopus/quicdoq). DNS over Quic is interesting
by itself, but it also provides an example for building an application different than
HTTP on top of Picoquic.

We are spending time bettering the implementation, and the documentation,
including a first pass at [documenting architecture and API](doc/architecture.md). Initially
the focus has been on correctness rather than performance. We will keep correctness,
but we will improve performance, especially in light of practical experience with 
applications. To facilitate performance tests, the demo program includes an
implementation of the [quic performance test protocol](doc/quicperf.md).
Suggestions for documentation, API, performance and more are wellcome. Feel free to
open an issue!

# Building Picoquic

Picoquic is developed in C, and can be built under Windows or Linux. Building the
project requires first managing the dependencies, [Picotls](https://github.com/h2o/picotls)
and OpenSSL. Please note that you will need a recent version of Picotls --
the Picotls API has evolved recently to support the latest version of QUIC. The
current code is tested against the Picotls version of Wed Nov 30 08:49:47 2022 +0900,
after commit `7e97d3e48e237b9a01227cf7f4b116325b356fc6`. The code uses OpenSSL
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

Thanks to check-ins from Deb Banerjee and Igor Lubashev for the build experience on Linux.

To build Picoquic on Linux, you need can either build picotls separately 
or use an integrated option. In both cases, you need first to install and 
build Openssl on your machine

To build step by step, you should:

 * Clone and compile Picotls, using cmake as explained in the Picotls documentation.

 * Clone and compile Picoquic:
~~~
   cmake .
   make
~~~

Instead of building picotls separately, you can use an integrated option 
(thanks to Paul E. Jones and Suhas Nandakumar for developing that):

 * Clone and compile Picoquic and Picotls in a single command:
~~~
   cmake -DPICOQUIC_FETCH_PTLS .
   make
~~~

Either way, you can verify that everything worked:

 * Run the test program `picoquic_ct` to verify the port.
 
The tests verify that the code compiles and runs correctly under Ubuntu,
using GitHub actions on Intel 64 bit VMs. We rely on user reports to verify
behavior on other architecture, e.g. ARM. Thanks to @defermelowie for testing on ARM 32 bits.

## Picoquic on MacOSX

Thanks to Frederik Deweerdt for ensuring that Picoquic runs on MacOSX. The build steps
are the same as for Linux. The tests verify that the code compiles and runs correctly under MacOS,
using GitHub actions on Intel 64 bit VMs. We rely on user reports to verify
behavior on other architecture, e.g. M1. Thanks to @defermelowie  for testing on M1.

## Picoquic on FreeBSD

Same build steps as Linux. Picoquic probably also works on other BSD variants, but only FreeBSD
has been tested so far.

## Developing applications

Sorry, not all that much documentation yet. This will come as we populate the wiki. Your
best bet is to look at the demonstration program "picoquicdemo" that is included in the
release. The sources are in "picoquicfirst/picoquicdemo.c". The `sample` folder
contains a code sample for a simplistic file transfer protocol, which might
be a good place to start. Look at the README.md file in the sample folder for
more details.

## Testing previous versions

The code is constantly updated to track the latest version of the specification. It currently
conforms to Version 1, and will negotiate support for the corresponding version `0x00000001` --
that is, QUIC Transport version 1. Picoquic will also accept negotiation of previous versions down to draft-27. 

# Creating QLOG Log Files

See [How To Produce QLOG files with picoquic](doc/QLOG.md)

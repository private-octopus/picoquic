# Picoquidemo and other programs

On Linux after building, the following executables are available in the project root directory.
All support "-h" argument to get the detailed usage:

* picohttp_ct: runs various HTTP tests
* picoquic_ct: runs various QUIC tests
	* with no arguments, runs all tests.
* picoquicdemo: QUIC/HTTP demo client and server for HTTP/3, HTTP/0.9, QUIC performance tests and Siduck(simple test of Datagram support)
* picoquic_sample: QUIC/HTTP sample demonstrating how to write an application using the picoquic stack.
  It is not meant to be actually used. See sample.md for detailed usage.

## HTTP Client and Server Usage

The program `picoquicdemo` can be used as a simple HTTP client or server. The usage is as follows:

* client: ./picoquicdemo servername serverportnumber HTTPpath
  * downloaded files will be in current directory. use -o for another folder 
  * example: ./picoquicdemo -o ../received 192.0.2.1 4433 index.html
* server: ./picoquicdemo -p portnumber
  * -p argument tells the program that it is acting as a server
  * HTML root folder is current directory by default. use -w for another folder
  * keys and certs are specified by -k and -c. See -h for more details.
  * example: ./picoquicdemo -w ../htmlroot -p 4433
* additional useful information for HTTP usage is available at:
  * [Without DNS Names Or Certs](https://github.com/private-octopus/picoquic/wiki/Testing-without-DNS-names-or-Certificates)
  * [Certs Using Lets Encrypt](https://github.com/private-octopus/picoquic/wiki/Import-key-and-cert-on-server-from-Let's-encrypt)
  * [Absolute Path](https://github.com/private-octopus/picoquic/wiki/Running-picoquicdemo-with-absolute-path)

The server code validates the file names provided by the
client, and will verify that the name does not contains "." or
other characters used in path traversal attacks. The code however
will follow symbolink links, even if they lead outside of the server's folder.

# QUIC Logging

* add -q $folder to cli commands so that QUIC logs are generated in that folder 
* you may use https://qvis.quictools.info/ by uploading the QLOG files and visualize the flows.


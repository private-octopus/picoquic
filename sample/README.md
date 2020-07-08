picoquic sample
===============

The sample program is a simple QUIC client/server demo.

Building
--------
picoquic\_sample is built as part of the compilation process of picoquic. It
will be available in the root folder.

Usage
-----
Usage:
    ../picoquic_sample client server_name port folder *queried_file
or :
    ../picoquic_sample server port cert_file private_key_file folder

Example
-------

Generate the certificates:
```
openssl req -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem
```
These commands will prompt a few questions, you don't need to put actual data
for this simple test.

Create a folder to hold server files:
```
mkdir server_files
echo "Hello world!" >> ./server_files/index.htm
```

And run the server:
```
./picoquic_sample server 4433 ./ca-cert.pem ./server-key.pem ./server_files
```

Then, test if you can reach it using the client:
```
./picoquic_sample client localhost 4433 /tmp index.htm
```

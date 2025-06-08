# ECH-ESNI

Picoquic implements Encrypted Client Hello (ECH) as specified in
[the ECH/ESNi draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).
The implementation relies on the support for ECH in
[picotls](https://github.com/h2o/picotls/wiki).
Picoquic only support the "shared mode" configuration of ECH, in which the same server
hosts both the "client facing" and "backend" servers.

# Server Side Support

The ECH support on the server is controlled by the API:
~~~
int picoquic_ech_configure_quic_ctx(picoquic_quic_t* quic, char const* ech_private_key_file_name, char const* ech_config_file_name);
~~~
This API takes two parameters:

* the path to a PEM file containing the private key use to decrypt the ECH option in the TLS Client Hello,
* the path to a text file containing a base64 encoded list of ECH configurations, as specified
  in [the ECH/ESNi draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

The ECH private key must be of type `secp256r1`, `x25519` or maybe `secp384r1`. This
three types of keys are supported if the picotls code is compiled with the OpenSSL
backend. (Support for the minicrypto and MbedTLS backends is work in progress.)

The public key in the ECH configuration must match the selected private key.

Once configured, ECH operation is transparent to the server.

## Creating the ECH Configuration

(TODO)

# Client side support

The ECH support on the client server is controlled by the same API as the server, allowing application to use
the same QUIC context in server mode and in client mode. If the application only needs the client mode, they do
not need to provide a private key or a configuration file. they could for example do
something like:
~~~
int ret = picoquic_ech_configure_quic_ctx(quic, NULL, NULL);
~~~
If ECH is configured, picoquic will either attempt ECH if it has access to a designated server
configuration, or "grease" the ECH extension as define in Section 6.2 of
[the ECH/ESNi draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

## Learning the ECH configuration

Picoquic has not yet implemented the capacity to query and parse HTTPS records. Instead,
we keep a cache of previously acquired records in the picoquic context. The typical
scenario would be:

1. Client attempts a connection to backend.example.com, ECH parameter is greased.

2. The connection is established. A call to `picoquic_is_ech_handshake(cnx)` returns 0
   (False), indicating that the ECH parameters were not processed. (Indeed, the were greased.)

3. The server ECH config, if any, is returned by the server in the ECH parameter, and cached
   in the picoquic context.

4. Some time later, the client creates a new connection to backend.example.com. The
   ECH parameters are retrieved, and the SNI is encrypted. A call to
   `picoquic_is_ech_handshake(cnx)` returns 1 (True).

This configuration is frowned upon in the draft, because it enables servers to
provide different values of the ECH configuration ID to different clients, and
thus use the ECh configuration ID to track the client across multiple connections.
This tracking is not possible if the ECH Configuration is retrieved from the
DNS for each connection, but then doing more DNS transaction also opens the
door to more tracking.

## SNI, IP address and client facing server

Picoquic server code assumes that the client "facing" and "backend" servers are located at the same IP
address. However, other QUIC implementations may not have that restriction. They may be
be supporting the "Split Mode" of ECH, in which the servers run at separate IP addresses.
Connecting directly to the backend server using ECH may not work, and in any case if
it did work the IP address would be specific to the backend server and would disclose
that server identity, defeating the purpose of ECH.

It is thus important that if an ECH configuration is present, the client retrieves the
"public server name" specified in the configuration, and connects to the address
of that server.

We note that there is some ambiguity in the spec. The ECH configuration specifies
the name of the client facing server, but it does not specify what port to use, or
what ALPN. To keep our implementation simple, we use some simplifications:

1. The ALPN in the outerClient hello will be set to H3.
2. The port number will be kept the same as the value specified in the command
   line.
3. Per spec, the outer SNI will be set to "public server name" value.
   
For example, if a test server is deployed on port 4433, we will assume that the client
facing server is running in the same process and listening on the same port.




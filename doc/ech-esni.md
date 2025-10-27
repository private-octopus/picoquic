# ECH-ESNI

Picoquic implements Encrypted Client Hello (ECH) as specified in
[the ECH/ESNi draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).
The implementation relies on the support for ECH in
[picotls](https://github.com/h2o/picotls/wiki).
Picoquic only support the "shared mode" configuration of ECH, in which the same server
hosts both the "client facing" and "backend" servers.

# Domain Name Configuration

The operation of ECH depends on the DNS -- although alternatives may be developed at some point.
The client follows a simple model. If the client application wants to connect to the domain "backend.example.com",
it retrieves the HTTPS records for that domain from the DNS (or the SVCB record if not using HTTPS).
There may be several such records, each documenting a priority, a target name and a set of parameters.
The client selects one of these HTTPS records. The target name of the selected record is the "client facing server".
That record may also provide the alternate port on which the server is running, and
the ECH Configuration of the server. The client will then:

* prepare a QUIC connection to the IP address and selected port of the client facing server,
  using the port number if one was specified in the HTTPS record -- or 443 if none was specified.
* add an ECH parameter to the TLS "Client Hello" specifying the SNI of the "backend" server,
  and possibly other parameters like the ALPN.
* establish the QUIC connection.

Once the connection is complete, the client will check whether the ECH negotiation
was successful. If may fail, for example if the client used an outdate version of the
ECH configuration. In that case, the server will provide an updated version in its
"ech-retry" parameters.

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

## Implementation in the demo program

When using the "picoquicdemo" server, the `ech_private_key_file_name` and `ech_config_file_name`
parameters can be set using the command line argument `-E`, as in for example:
~~~
picoquicdemo -k private_key.pem -c cert.pem -E ech_key.pem ech_config.txt -p 443
~~~
We see here two private keys:

1. The key use to sign the TLS handshake (`private_key.pem` in the example),
2. The key used to negoatiate the ECH encryption (`ech_key.pem` in the example).

It is possible to use the same key (and the same file) for both functions, but only if it is using
an Elliptic Curve like `secp256r1`, `secp384r1` or `x25519`.

The ECH configuration includes the description of the private key associated
with the ECH encryption key, and is paired with it, much like the TLS key is paired with
the certificate.

## Creating the ECH Configuration

The ECH configuration may be created on the first use of ECH by providing a "public name" using
the `-y` parameter, as is for example:
~~~
picoquicdemo -k private_key.pem -c cert.pem -y test.example.com -E ech_key.pem ech_config.txt -p 443
~~~
In that example, picoquic will create an ECH configuration in which:

1. The HPKE parameters are derived from the type of the ECH key,
2. The public key is the public key corresponding to the ECH key,
3. The public name is the value specified (`test.example.com` in the example).

Picoquic will compose the ECH configuration, encode it in base64, and then save it in the
ECH configuration file (`ech_config.txt` in the example). That base64 string should be
set as the value of the `ech=` parameter in the HTTPS parameter published by the server.

# Client side support

The ECH support on the client server is controlled by the same API as the server, allowing application to use
the same QUIC context in server mode and in client mode. If the application only needs the client mode, they do
not need to provide a private key or a configuration file. they could for example do
something like:
~~~
ret = picoquic_ech_configure_quic_ctx(quic, NULL, NULL);
~~~
When starting a connection, an endpoint that knows the value of the ECH option can configure
can configure a connection context by using the API:
~~~
int picoquic_ech_configure_client(picoquic_cnx_t* cnx, uint8_t* config_data, size_t config_length);
~~~
This API must be used before the connection is "started". A typical sequence would be:
~~~
/* Create a QUIC context */
picquic_quic_t * quic = picoquic_create(...);
if (quic != NULL){
    /* Set additional context parameters if needed, e.g. logging options */
    ...
    /* Configure ECH for the QUIC context */
    ret = picoquic_ech_configure_quic_ctx(quic, NULL, NULL);
    if (ret == 0){
        /* Create a client connection
        * The "server_addr" parameter is set to the address of the "facing" server.
        * The "sni" parameter is set to the name of the "backend" server.
        */
        picoquic-cnx_t * cnx = picoquic_create_cnx(quic,
                    initial_cid,
                    picoquic_null_connection_id,
                    (struct sockaddr*)server_addr,
                    current_time,
                    proposed_version, sni, alpn, 1);
        if (cnx != NULL){
            /* Set connection parameters as required */
            ...
            /* Set ECH configuration of the connection */
            ret = picoquic_ech_configure_client(cnx, config_data, config_length);
            if (ret == 0){
                /* Start the connection */
                ret = picoquic_start_client_cnx(test_ctx->cnx_client);
            }
        }
    }
}
~~~
Note that if ECH is configured in the QUIC context using `picoquic_ech_configure_quic_ctx`
but the code does not configure ECH for the connection using `picoquic_ech_configure_client`,
picoquic will use a "Grease" version of the ECH parameter in the outgoing "Client Hello".

## Implementation in the demo program

The client side ECH option is configured by using the "-K" configuration
option, which takes as parameter a base64 encoded ECH configuration.
One possible way to use that would be:

1. Use a program such as `dig` to obtain the HTTPS record for the backend service,
2. Use a shell script to extract the `ech` configuration from the selected
   HTTPS record and the IP address of the client facing server,
3. Document the parameters in the command line arguments:
   - Set the IP address and port number to the IP address of the client facing server,
     and to the port number documented in the HTTPS record (or 443 by default).
   - Document the name of the backend server in the "-n" option.
   - Document the ECH configuration in the "-K" option.

If the configuration is wrong, the picoquicdemo program will print out the
base64 encoded value of the "retry" configuration provided by the server.








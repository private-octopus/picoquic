# Support for post-quantum algorithms

The advent of a cryptographically relevant quantum computer (CRQC) would render state-of-the-art,
traditional public key algorithms deployed today obsolete, as the mathematical assumptions
underpinning their security would no longer hold (see: [RFC 9958](https://datatracker.ietf.org/doc/html/rfc9958)).
Several "post quantum" algorithm are being developed, covering both key exchange and
certificate verifications.

Picoquic first priority is to support Post Quantum Key Exchange
algorithms, in order to protect deployments from ""harvest now, decrypt later" (HNDL)
attack where a malicious actor with adequate resources can launch an attack to store
sensitive encrypted data today that they hope to decrypt once a CRQC is available.

There is some controversy on the proper way to deploy these algorithms.
On one hand, we need protection against HDNL attacks. On the other hand,
Post Quantum Key Exchange algorithms are just beginning to be deployed,
and there is some risk that the algorithms or their implementation
will turn on to be fragile. The IETF position is stated in the table of
[TLS Supported Groups[(https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)]
published by the IANA, which assigns to each registered algorithm
a status "RECOMMENDED" or not. The algorithms currently defined in
this table are:

| Algorithm | Recommended | Description
|-------------- | ----------- | ---------------------
| [MLKEM512](https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement/) | N 	| FIPS 203 version of ML-KEM-512
| [MLKEM768](https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement/) | N 	| FIPS 203 version of ML-KEM-768
| [MLKEM1024](https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement/) | N | FIPS 203 version of ML-KEM-1024
| [SecP256r1MLKEM512](https://datatracker.ietf.org/doc/html/draft-rosomakho-tls-ecdhe-mlkem512) | N | Combining secp256r1 ECDH with ML-KEM-512
| [MLKEM512X25519](https://datatracker.ietf.org/doc/html/draft-rosomakho-tls-ecdhe-mlkem512) | N | Combining ML-KEM-512 with X25519 ECDH
| [SecP256r1MLKEM768](https://www.rfc-editor.org/info/rfc10024/)  | N 	| Combining secp256r1 ECDH with ML-KEM-768
| [X25519MLKEM768](https://www.rfc-editor.org/info/rfc10024/) | Y | Combining X25519 ECDH with ML-KEM-768
| [SecP384r1MLKEM1024](https://www.rfc-editor.org/info/rfc10024/) |	N | Combining secp384r1 ECDH with ML-KEM-1024

The only recommended algorithm is X25519MLKEM768, i.e., the combination of the "classic" X22519 algorithm
with the post quantum algorithm ML-KEM-768. This is a "hybrid" algorithm, designed to be robust at least
as long as one of X22519 and ML-KEM-768 remains robust. If a flaw is discovered in ML-KEM-768, the algorithm
will remain robust until CRQC become available and able to break X22519.

Picoquic follows the IETF recommendation and provide a compile option in CMake,
PQC_RECOMMENDED_ONLY, which defaults to ON: only make available the PQC algorithms
recommended by the IETF. Setting the option to OFF will compile PICOQUIC with
the option PICOQUIC_WITH_ALL_PQC_ALGORITHMS defined, which will make all algorithm available
even if not recommended.

Of course, algorithms can only be made available if they are
supported by the underlying cryptographic libary. As of this writing, this is only true
for the latest versions of OpenSSL.


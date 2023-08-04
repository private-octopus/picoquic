# Running without openssl

Picoquic was originally built to use the OpenSSL functions made available through "pictotls".
There are however environments for which OpenSSL is not available, or in which loading
OpenSSL is not desirable. In these environments, we want to use alternatives. Here is a list
of the functions that we want, and potential alternatives.

Function | Usage | Alternatives 
---------|-------|--------------
SHA256  | Key derivation | minicrypto. Could also use mbed or bcrypt on some platforms.
aes128gcm | local secrets |  Minicrypto, but it is painfully slow. On x86/64, ptls_fusion works great. Bcrypt on Windows. MbedTLS on ARM.
aes128gcmsha256 | Cipher suite used in initial packets, required for interop | Same issue as AES_GCM_128
aes256gcmsha384 | Used for higher security | Pretty much same issue as AES_GCM_128. Not clear whether there is support in MbedTLS
chacha20poly1305sha256 | Better performance than aes128gcm if hardware support is not available. | Minicrypto, but the performance is limited. Maybe MbedTLS.
init_sign_certificate | Certificate signature | Minicrypto only supports some types of certificates.
set_tls_key_openssl | Set the root key used to sign CERT | Minicrypto, but only some types of keys.
set_tls_root_certificates | Set the root certificates used for verification | Maybe load some PEM file?
set_random_provider | Set a random number provider | Investigate. Bcrypt comes with `cryptogenrandom`

# Software structure

The original code directly linked into openssl, while using some of the abstractions proposed
by picotls. We want a more structure solution, loading algorithms and function in tables,
and then using function pointers or other indirections.

The code could be organized around provider initialization and release functions:

* the module tls_api calls each of the registered providers.
* if the provider is available, it calls a set of API to register algorithms and ciphersuites.
* if the provider is not available, the provider specific calls are hidden behind `ifdef` and not compiled or linked.
* for each table, the code looks at functions in order of preference. It takes call to load algorithms,
  ciphersuites or functions, but retains the first registered value, ignoring the others.
* upon exit, tls_api calls each registered provider to free resources, etc.

One small complexity: PTLS_FUSION is desirable, but uses more memory than other implementations of AES_GCM.
The APIs include a memory precedence flag, which would be a function of the provider. Consider a simplification?

The following PTLS API can be leveraged:

* For SHA256: `ptls_hash_algorithm_t`.
* For AEAD algorithms like aes128gcm: `ptls_aead_algorithm_t`
* For key exchange suites: `ptls_key_exchange_algorithm_t`

# Progressive development

We probably want to use a series of simple steps, so we can verify the effects and perform tests after each change.
We will start with a set of providers, in the following order:

* PTLS_FUSION: this is controlled by a compilation flag. It will be preferred if the flag is set.
* Bcrypt: only on windows platforms. Not sufficient by itself, because the key exchange algorithms have not been ported._
* MbedTLS: once it is ported.
* OpenSSL: if available.
* Minicrypto: as the final place holder, if nothing else is available.


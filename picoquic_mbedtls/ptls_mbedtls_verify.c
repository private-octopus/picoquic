/*
* Copyright (c) 2023, Christian Huitema
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to
* deal in the Software without restriction, including without limitation the
* rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
* sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/build_info.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"
#include "ptls_mbedtls.h"

#if 0

/* Handling of certificates.
* Certificates in picotls are used both at the client and the server side.
* 
* The server is programmed with a copy of the certificate chain linking
* the local key and identity to a certificate authority. Picotls formats
* that key and sends it as part of the "server hello". It is signed with
* the server key.
* 
* On the server side, picotls expects?
* 
* The client is programmed with a list of root certificates. It should
* process the list received from the server and verifies that it does
* correctly link the server certificate to one of the certificates in the
* root list.
* 
* Mbedtls documents a series of certificate related API in `x509_crt.h`.
* 
* On the server side, we read the certificates from a PEM encoded
* file, and provide it to the server.
* 
* int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen)
*     => parse the DER code in the buffer, documents a cerificate chain
*        in MbetTLS format.
* 
* int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen)
*    => Parse one DER-encoded or one or more concatenated PEM-encoded certificates and
*       add them to the chained list. 
* 
* int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt, mbedtls_x509_crt *trust_ca, mbedtls_x509_crl *ca_crl, const char *cn, uint32_t *flags, int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void *p_vrfy)
*    => check the certificate chain (crt) against a list of trusted ca (trust_ca) and
*       a specified "common name". "ca_crl" is a revocation list.
* 
* Public key operations such as "verify message" require a key-id.  We should obtain that key ID by using "psa_import_key":
* 
* psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data, size_t data_length, mbedtls_svc_key_id_t *key)
* 
* The data and data length are probably obtained 
*/

/* load a PEM file in memory, adding a final 0 byte per MBEDTLS expectations */
int ptls_mbedtls_load_file(char const* file_name, unsigned char** buf, size_t* n);

/* verify certificate.
* Picotls and then picoquic use a two phase API:
* 
* - During initialization, prepare a "verify certificate callback"
* - During the handshake, picotls executes the callback.
* 
* Picotls verifies certificates using the "verify_certificate" callback.
* 
* if ((ret = tls->ctx->verify_certificate->cb(tls->ctx->verify_certificate,
*       tls, server_name, &tls->certificate_verify.cb,
*       &tls->certificate_verify.verify_ctx, certs, num_certs)) != 0)
*           goto Exit;
*
* This is implemented using the function mbedtls_verify_certificate,
* documented during the initialization of the "cb" structure,
* ptls_mbedtls_verify_certificate_t. The function pointer is
* the first member of that structure, followed by other arguments.
* The callback structure is passed as the first argument in the
* callback, with type "self".
* 
* The callback should return 0 if the certificate is good. The call may
* also set the value of tls->certificate_verify.cb and 
* tls->certificate_verify.verify_ctx. If these are set, picotls will
* then use tls->certificate_verify.cb to verify that the TLS messages
* are properly signed using that certificate.
*
* The function mbedtls_verify_certificate is implemented using the
* function "mbedtls_x509_crt_verify", which has the following arguments:
* 
* - A chain of certificates, starting from the server certificate and hopefully
*   going all the way to one of the root certificates. In our code, this
*   is obtained by parsing the "certs" argument provided by picotls, which
*   is an iovec vector of length numcerts, with one entry per certificate in
*   the CERTS parameter received from the server.
* - The chain of trusted certificate authorities. In our case, that list is
*   initialized during the call to `ptls_mbedssl_init_verify_certificate`,
*   loading certificates from a `root` file.
* - A certificate revocation list. We leave that parameter NULL for now.
* - The expected server name, a NULL terminated string.
* - A "verify" function pointer, and its argument. This function 
* The call returns 0 (and flags set to 0) if the chain was verified and valid,
* MBEDTLS_ERR_X509_CERT_VERIFY_FAILED if the chain was verified but found to
* be invalid, in which case *flags will have one or more MBEDTLS_X509_BADCERT_XXX
* or MBEDTLS_X509_BADCRL_XXX flags set, or another error
* (and flags set to 0xffffffff) in case of a fatal error encountered
* during the verification process. 
* 
* The verify callback is a user-supplied callback that can clear / modify / add
* flags for a certificate. If set, the verification callback is called for each
* certificate in the chain (from the trust-ca down to the presented crt).
* The parameters for the callback are: (void *parameter, mbedtls_x509_crt *crt,
* int certificate_depth, int *flags). With the flags representing current flags
* for that specific certificate and the certificate depth from the bottom
* (Peer cert depth = 0). Function pointer and parameters can be set in the call
* to `ptls_mbedssl_init_verify_certificate`.
* 
* If the certificate verification is successfull, the code sets the pointer
* and the context for the certificate_verify callback:
* 
* struct {
*    int (*cb)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature);
*    void *verify_ctx;
* } certificate_verify;
* 
* The structure "certificate_verify" is allocated as part of the PTLS context. We will
* allcoate a a "ptls_mbetls_certificate_verify_ctx_t" ctx as part of the
* 
* The verify callback is implemented using `psa_verify_message`, which takes the following
* arguments:
* 
* psa_status_t psa_verify_message(psa_key_id_t key,
*                                psa_algorithm_t alg,
*                                const uint8_t * input,
*                                size_t input_length,
*                                const uint8_t * signature,
*                                size_t signature_length);
*
* The public key ID will be set from the certificate proposed by the server. The
* input and length of the data to be signed are derived from the data parameter
* in the callback, and the signature and length from the signature parameter of
* the callback. The "alg" parameter of type "psa_algorithm_t" will have to
* be derived from the algo parameter of the callback, which is a 16 bit
* "signature scheme" (see
* https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme).
* 
* Picotls will use that callback exactly once, then reset the callback
* pointer to NULL. It does not reset of free the "verify_ctx" -- if necessary,
* the value there should be reset after the first call.
*/

typedef struct st_mbedtls_message_verify_ctx_t {
    psa_key_id_t key_id;
} mbedtls_message_verify_ctx_t;

uint16_t mbedtls_verify_sign_algos[] = {
    0x0201, 0x0203, 0x0401, 0x0403, 0x501, 0x0503, 0x0601, 0x0603,
    0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
    0xFFFF
};

static int mbedtls_verify_sign(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature)
{
    /* Obtain the key parameters, etc. */
    int ret = 0;
    psa_algorithm_t alg = PSA_ALG_NONE;
    mbedtls_message_verify_ctx_t * message_verify_ctx = (mbedtls_message_verify_ctx_t*)verify_ctx;

    if (message_verify_ctx == NULL) {
        ret = PTLS_ERROR_LIBRARY;
    } else if (data.base != NULL) {
        /* Picotls will call verify_sign with data.base == NULL when it
         * only wants to clear the memory. This is not an error condition. */
         /* Find the PSA_ALG for the signature scheme is supported */
        switch (algo) {
        case 0x0201: /* PTLS_SIGNATURE_RSA_PKCS1_SHA1 */
            alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_1);
            break;
        case 0x0203: /*	ecdsa_sha1 */
            alg = PSA_ALG_ECDSA(PSA_ALG_SHA_1);
            break;
        case 0x401: /* PTLS_SIGNATURE_RSA_PKCS1_SHA256 */
            alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
            break;
        case 0x0403: /*  PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 */
            alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            break;
#if 0
        case 0x0420: /* rsa_pkcs1_sha256_legacy */
            break;
        case 0x0520: /* rsa_pkcs1_sha384_legacy */
            break;
#endif
        case 0x501: /* rsa_pkcs1_sha384 */
            alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_384);
            break;
        case 0x0503: /* PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 */
            alg = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
            break;
        case 0x0601: /* rsa_pkcs1_sha512  */
            alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512);
            break;
        case 0x0603: /* PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 */
            alg = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
            break;
        case 0x0804: /* PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256 */
            alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
            break;
        case 0x0805: /* PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384 */
            alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_384);
            break;
        case 0x0806: /* PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512 */
            alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
            break;
        case 0x0807: /* PTLS_SIGNATURE_ED25519 */
            alg = PSA_ALG_ED25519PH;
            break;
        case 0x0808: /* PTLS_SIGNATURE_ED448 */
            alg = PSA_ALG_ED448PH;
            break;
        default:
            break;
        }

        if (alg == PSA_ALG_NONE) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        }
        else {
            psa_status_t status = psa_verify_message(message_verify_ctx->key_id, alg, data.base, data.len, signature.base, signature.len);

            if (status != PSA_SUCCESS) {
                switch (status) {
                case PSA_ERROR_NOT_PERMITTED: /* The key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does not permit the requested algorithm. */
                    ret = PTLS_ERROR_INCOMPATIBLE_KEY;
                    break;
                case PSA_ERROR_INVALID_SIGNATURE: /* The calculation was performed successfully, but the passed signature is not a valid signature. */
                    ret = PTLS_ALERT_DECRYPT_ERROR;
                    break;
                case PSA_ERROR_NOT_SUPPORTED:
                    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                    break;
                case PSA_ERROR_INSUFFICIENT_MEMORY:
                    ret = PTLS_ERROR_NO_MEMORY;
                    break;
                default:
                    ret = PTLS_ERROR_LIBRARY;
                    break;
                }
            }
        }
    }
    /* destroy the key because it is used only once. */
    if (message_verify_ctx != NULL) {
        psa_destroy_key(message_verify_ctx->key_id);
        free(message_verify_ctx);
    }
    return ret;
}

static int mbedtls_verify_certificate(ptls_verify_certificate_t *_self, ptls_t *tls, const char *server_name,
    int (**verifier)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **verify_data, ptls_iovec_t *certs,
    size_t num_certs)
{
    size_t i;
    int ret = 0;
    ptls_mbedtls_verify_certificate_t *self = (ptls_mbedtls_verify_certificate_t *)_self;
    mbedtls_x509_crt chain_head = { 0 };

    *verifier = NULL;
    *verify_data = NULL;



    /* If any certs are given, convert them to MbedTLS representation, then verify the cert chain. If no certs are given, just give
    * the override_callback to see if we want to stay fail open. */
    if (num_certs == 0) {
        ret = PTLS_ALERT_CERTIFICATE_REQUIRED;
    } else {
        mbedtls_x509_crt* previous_chain = &chain_head;
        mbedtls_x509_crt_init(&chain_head);

        for (i = 0; i != num_certs; ++i) {
            ret = mbedtls_x509_crt_parse_der(previous_chain, certs[i].base, certs[i].len);
            if (i != 0) {
                if (previous_chain->next == NULL) {
                    ret = PTLS_ALERT_BAD_CERTIFICATE;
                    break;
                }
                previous_chain = previous_chain->next;
            }
        }

        if (ret == 0) {
            uint32_t flags = 0;

            int verify_ret = mbedtls_x509_crt_verify(&chain_head, self->trust_ca, NULL /* ca_crl */, server_name, &flags,
                self->f_vrfy, self->p_vrfy);

            if (verify_ret != 0) {
                switch (verify_ret) {
                    case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED: 
                        /* if the chain was verified but found to be invalid, in which case
                        * flags will have one or more MBEDTLS_X509_BADCERT_XXX
                        * or MBEDTLS_X509_BADCRL_XXX flags set, or another 
                        * error(and flags set to 0xffffffff) in case of a fatal error
                        * encountered during the verification process. */
                        ret = PTLS_ALERT_BAD_CERTIFICATE;
                        break;
                    default:
                        ret = PTLS_ERROR_LIBRARY;
                        break;
                }
            }
        }
        
        if (ret == 0) {
            mbedtls_message_verify_ctx_t* message_verify_ctx = (mbedtls_message_verify_ctx_t*)
                malloc(sizeof(mbedtls_message_verify_ctx_t));
            if (message_verify_ctx == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
            }
            else {
                psa_status_t status;
                psa_key_attributes_t attributes;
                memset(&attributes, 0, sizeof(attributes));
                memset(message_verify_ctx, 0, sizeof(mbedtls_message_verify_ctx_t));

                status = mbedtls_pk_get_psa_attributes(&chain_head.next->pk, PSA_KEY_USAGE_VERIFY_MESSAGE, &attributes);
                if (status == PSA_SUCCESS) {
                    status = mbedtls_pk_import_into_psa(&chain_head.next->pk, &attributes, &message_verify_ctx->key_id);
                }
                if (status != PSA_SUCCESS) {
                    ret = PTLS_ERROR_LIBRARY;
                    free(message_verify_ctx);
                }
                else {
                    *verifier = mbedtls_verify_sign;
                    *verify_data = message_verify_ctx;
                }
            }
        }
    }

    if (chain_head.next != NULL) {
        mbedtls_x509_crt_free(chain_head.next);
    }
    return ret;
}

/* Read certificates from a file using MbedTLS functions.
* We only use the PEM function to parse PEM files, find
* up to 16 certificates, and convert the base64 encoded
* data to DER encoded binary. No attempt is made to verify
* that these actually are certificates.
*/
int picoquic_mbedtls_get_certs_from_file(char const * pem_fname, ptls_iovec_t** pvec, size_t * count)
{
    int ret = 0;
    *pvec = (ptls_iovec_t*)malloc(sizeof(ptls_iovec_t) * 16);

    *count = 0;
    if (*pvec == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    } else {
        size_t buf_length;
        unsigned char* buf = NULL;
        /* The load file function simply loads the file content in memory */
        if ((ret = ptls_mbedtls_load_file(pem_fname, &buf, &buf_length)) == 0) {
            size_t length_already_read = 0;

            while (ret == 0 && *count < 16 && length_already_read < (size_t)buf_length) {
                mbedtls_pem_context pem = { 0 };
                size_t length_read = 0;

                /* PEM context setup. */
                mbedtls_pem_init(&pem);
                /* Read a buffer for PEM information and store the resulting data into the specified context buffers. */
                ret = mbedtls_pem_read_buffer(&pem,
                    "-----BEGIN CERTIFICATE-----",
                    "-----END CERTIFICATE-----",
                    buf + length_already_read, NULL, 0, &length_read);
                if (ret == 0) {
                    /* Certificate was read successfully. PEM buffer contains the base64 value */
                    uint8_t* cert = (uint8_t*)malloc(pem.private_buflen);
                    if (cert == NULL) {
                        ret = PTLS_ERROR_NO_MEMORY;
                    }
                    else {
                        memcpy(cert, pem.private_buf, pem.private_buflen);
                        (*pvec)[*count].base = cert;
                        (*pvec)[*count].len = pem.private_buflen;
                        *count += 1;
                    }
                }
                mbedtls_pem_free(&pem);
                length_already_read += length_read;
            }

            free(buf);
        }
    }
    return ret;
}

int ptls_mbedtls_load_certificates(ptls_context_t *ctx, char const *cert_pem_file)
{
    return picoquic_mbedtls_get_certs_from_file(cert_pem_file, &ctx->certificates.list,
        &ctx->certificates.count);
}

/* Creating the call back. This API is not really mandated by picotls. The "backend"
* merely has to provide a "certicate verifier" callback. We consider two ways of
* providing this callback: an API very close to the details of the MBedTLS code,
* with a list of explicit parameters, and a "portable" API whose only
* parameter is a file name for the list of trusted certificates. 
*/

int ptls_mbedssl_init_verify_certificate_complete(ptls_context_t * ptls_ctx,
    mbedtls_x509_crt* trust_ca, mbedtls_x509_crl* trust_crl,
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void* p_vrfy)
{
    int ret = 0;
    ptls_mbedtls_verify_certificate_t* verifier =
        (ptls_mbedtls_verify_certificate_t*)malloc(sizeof(ptls_mbedtls_verify_certificate_t));
    if (verifier == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }
    else {
        memset(verifier, 0, sizeof(ptls_mbedtls_verify_certificate_t));
        verifier->super.cb = mbedtls_verify_certificate;
        verifier->super.algos = mbedtls_verify_sign_algos; /* list of supported algorithms, end with 0xFFFF */
        verifier->trust_ca = trust_ca;
        verifier->trust_crl = trust_crl;
        verifier->f_vrfy = f_vrfy;
        verifier->p_vrfy = p_vrfy;
        ptls_ctx->verify_certificate = &verifier->super;
    }
    return ret;
}

int ptls_mbedtls_init_verify_certificate(ptls_context_t* ptls_ctx, char const* pem_fname)
{
    int ret = 0;
    mbedtls_x509_crt* chain_head = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt));

    if (chain_head == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }
    else {
        int psa_ret;
        mbedtls_x509_crt_init(chain_head);

        psa_ret = mbedtls_x509_crt_parse_file(chain_head, pem_fname);
        if (psa_ret == 0) {
            ret = ptls_mbedssl_init_verify_certificate_complete(ptls_ctx,
                chain_head, NULL, NULL, NULL);
        }
        else if (psa_ret > 0) {
            /* some of the certificates could not parsed */
            ret = PTLS_ALERT_BAD_CERTIFICATE;
        }
        else if (psa_ret == PSA_ERROR_INSUFFICIENT_MEMORY) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
        else {
            ret = PTLS_ERROR_LIBRARY;
        }

        if (ret != 0 && chain_head != NULL) {
            mbedtls_x509_crt_free(chain_head);
        }
    }
    return ret;
}

void ptls_mbedtls_dispose_verify_certificate(ptls_context_t* ptls_ctx)
{
    ptls_mbedtls_verify_certificate_t* verifier =
        (ptls_mbedtls_verify_certificate_t*)ptls_ctx->verify_certificate;
    if (verifier != NULL) {
        if (verifier->trust_ca != NULL) {
            mbedtls_x509_crt_free(verifier->trust_ca);
            verifier->trust_ca = NULL;
        }
        if (verifier->trust_crl != NULL) {
            mbedtls_x509_crl_free(verifier->trust_crl);
        }
        memset(verifier, 0, sizeof(ptls_mbedtls_verify_certificate_t));
        free(verifier);
        ptls_ctx->verify_certificate = NULL;
    }
}
#endif
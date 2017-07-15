#ifdef WIN32
#include "wincompat.h"
#endif
#include <stdio.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "picoquic.h"

/*
* Using the open ssl library to load the test certificate
*/

static X509* openPemFile(char* filename)
{

    X509* cert = X509_new();
    BIO* bio_cert = BIO_new_file(filename, "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    return cert;
}

static int get_certificates(char * pem_fname, ptls_iovec_t ** list, int * nb_certs)
{
    int ret = 0;
    size_t count = 0;
    X509 *cert;
    static ptls_iovec_t certs[16];

    *nb_certs = 0;
    *list = NULL;

    cert = openPemFile(pem_fname);

    if (cert == NULL)
    {
        ret = -1;
    }
    else
    {
        ptls_iovec_t *dst = certs + count++;
        dst->len = i2d_X509(cert, &dst->base);
    }

    *nb_certs = count;
    *list = certs;

    return ret;
}

static void SetSignCertificate(char * keypem, ptls_context_t * ctx)
{
    static ptls_openssl_sign_certificate_t signer;

    EVP_PKEY *pkey = EVP_PKEY_new();
    BIO* bio_key = BIO_new_file(keypem, "rb");
    PEM_read_bio_PrivateKey(bio_key, &pkey, NULL, NULL);
    ptls_openssl_init_sign_certificate(&signer, pkey);
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &signer.super;
}

void picoquic_crypto_random(picoquic_quic * quic, void * buf, size_t len)
{
    int ret = 0;
    ptls_context_t *ctx = (ptls_context_t *)quic->tls_master_ctx;

    return (ctx->random_bytes(buf, len));

}

int picoquic_master_tlscontext(picoquic_quic * quic, char * cert_file_name, char * key_file_name)
{
    /* Create a client context or a server context */
    int ret = 0;
    ptls_context_t *ctx;
    ptls_openssl_verify_certificate_t * verifier = NULL;

    ctx = (ptls_context_t *)malloc(sizeof(ptls_context_t));

    if (ctx == NULL)
    {
        ret = -1;
    }
    else
    {
        memset(ctx, 0, sizeof(ptls_context_t));
        ctx->random_bytes = ptls_openssl_random_bytes;
        ctx->key_exchanges = ptls_openssl_key_exchanges;
        ctx->cipher_suites = ptls_openssl_cipher_suites;

        if (quic->flags&picoquic_context_server)
        {
            /* Read the certificate file */

            if (get_certificates(cert_file_name, &ctx->certificates.list, &ctx->certificates.count) != 0)
            {
                ret = -1;
            }
            else
            {
                SetSignCertificate(key_file_name, ctx);
            }
        }
        else
        {
            verifier = (ptls_openssl_verify_certificate_t *)malloc(sizeof(ptls_openssl_verify_certificate_t));
            ptls_openssl_init_verify_certificate(verifier, NULL);
            ctx->verify_certificate = &verifier->super;
        }

        if (ret == 0)
        {
            quic->tls_master_ctx = ctx;
        }
        else
        {
            free(ctx);
        }
    }

    return ret;
}

/*
 * Creation of a TLS context
 */
int picoquic_tlscontext_create(picoquic_quic * quic, picoquic_cnx * cnx)
{
    int ret = 0;
    cnx->tls_ctx = ptls_new((ptls_context_t *) quic->tls_master_ctx, (quic->flags&picoquic_context_server)?1:0);

    if (cnx->tls_ctx == NULL)
    {
        ret = -1;
    }

    return ret;
}

void picoquic_tlscontext_free(void * ctx)
{
    ptls_free((ptls_t *)ctx);
}

/*
 * Arrival of a handshake item (frame 0) in a packet of type T.
 * This triggers an optional progress of the connection.
 * Different processing based on packet type:
 *
 * - Client side initialization. Include transport parameters.
 *   May provide 0-RTT initialisation.
 * - Client Initial Receive. Accept the connection. Include TP.
 *   May provide 0-RTT initialization.
 *   Provide 1-RTT init.
 * - Server Clear Text. Confirm the client side connection.
 *   May provide 1-RTT init
 */

int picoquic_tlsinput_segment(picoquic_cnx * cnx,
    uint8_t * bytes, size_t length, size_t * consumed, struct st_ptls_buffer_t * sendbuf)
{
    ptls_t * tls_ctx = (ptls_t *)cnx->tls_ctx;
    size_t inlen = 0, roff = 0;
    int ret = 0;

    ptls_buffer_init(sendbuf, "", 0);

    /* Provide the data */
    while (roff < length && (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
    {
        inlen = length - roff;
        ret = ptls_handshake(tls_ctx, sendbuf, bytes + roff, &inlen, NULL);
        roff += inlen;
    }

    *consumed = roff;

    return ret;
}

int picoquic_initialize_stream_zero(picoquic_cnx * cnx)
{
    int ret = 0;
    struct st_ptls_buffer_t sendbuf;
    ptls_t * tls_ctx = (ptls_t *)cnx->tls_ctx;

    ptls_buffer_init(&sendbuf, "", 0);
    ret = ptls_handshake(tls_ctx, &sendbuf, NULL, NULL, NULL);

    if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
    {
        if (sendbuf.off > 0)
        {
            ret = picoquic_add_to_stream(cnx, 0, sendbuf.base, sendbuf.off);
        }
        ret = 0;
    }
    else
    {
        ret = -1;
    }

    ptls_buffer_dispose(&sendbuf);

    return ret;
}



int picoquic_tlsinput_stream_zero(picoquic_cnx * cnx)
{
    int ret = 0;
    picoquic_stream_data * data = cnx->first_stream.stream_data;
    struct st_ptls_buffer_t sendbuf;

    if (data != NULL &&
        data->offset > cnx->first_stream.consumed_offset)
    {
        return 0;
    }

    ptls_buffer_init(&sendbuf, "", 0);

    while (
        (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && 
        data != NULL && data->offset <= cnx->first_stream.consumed_offset)
    {
        size_t start = (size_t)(cnx->first_stream.consumed_offset - data->offset);
        size_t consumed = 0;

        ret = picoquic_tlsinput_segment(cnx, data->bytes + start,
            data->length - start, &consumed, &sendbuf);

        cnx->first_stream.consumed_offset += consumed;
        
        if (start + consumed >= data->length)
        {
            free(data->bytes);
            cnx->first_stream.stream_data = data->next_stream_data;
            free(data);
            data = cnx->first_stream.stream_data;
        }
    }

    if (ret == 0)
    {
        switch (cnx->cnx_state)
        {
        case picoquic_state_client_init:
        case picoquic_state_client_handshake_start:
        case picoquic_state_client_handshake_progress:
            /* Extract and install the client 1-RTT key */
            cnx->cnx_state = picoquic_state_client_almost_ready;
            break;
        case picoquic_state_server_init:
        case picoquic_state_server_handshake_progress:
            /* Extract and install the server 0-RTT and 1-RTT key */
            cnx->cnx_state = picoquic_state_server_almost_ready;
            break;
        case picoquic_state_client_almost_ready:
        case picoquic_state_client_ready:
        case picoquic_state_server_ready:
        case picoquic_state_server_almost_ready: 
        case picoquic_state_disconnected:
        default:
            break;
        }
    }
    else if (ret == PTLS_ERROR_IN_PROGRESS && cnx->cnx_state == picoquic_state_client_init)
    {
        /* Extract and install the client 0-RTT key */
    }

    if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
    {
        if (sendbuf.off > 0)
        {
            ret = picoquic_add_to_stream(cnx, 0, sendbuf.base, sendbuf.off);
        }
        ret = 0;
    }
    else
    {
        ret = -1;
    }

    ptls_buffer_dispose(&sendbuf);

    return ret;
}
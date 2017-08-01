/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
    ptls_iovec_t * certs;

    *nb_certs = 0;
    *list = NULL;

	certs = (ptls_iovec_t *)malloc(sizeof(ptls_iovec_t) * 16);

	if (certs == NULL)
	{
		ret = -1;
	}
	else
	{
		cert = openPemFile(pem_fname);
		memset(certs, 0, sizeof(ptls_iovec_t) * 16);

		if (cert == NULL)
		{
			ret = -1;
		}
		else
		{
			ptls_iovec_t *dst = &certs[count++];
			dst->len = i2d_X509(cert, &dst->base);
		}
	}
    *nb_certs = count;
    *list = certs;

    return ret;
}

static int SetSignCertificate(char * keypem, ptls_context_t * ctx)
{
	int ret = 0;
    ptls_openssl_sign_certificate_t * signer;
	EVP_PKEY *pkey = EVP_PKEY_new();

	signer = (ptls_openssl_sign_certificate_t *)malloc(sizeof(ptls_openssl_sign_certificate_t));

	if (signer == NULL || pkey == NULL)
	{
		ret = -1;
	}
	else
	{
		BIO* bio_key = BIO_new_file(keypem, "rb");
		EVP_PKEY * ret_pkey = PEM_read_bio_PrivateKey(bio_key, &pkey, NULL, NULL);
		if (ret_pkey == NULL)
		{
			ret = -1;
		}
		else
		{
			ret = ptls_openssl_init_sign_certificate(signer, pkey);
		}
		ctx->sign_certificate = &signer->super;
	}

	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
	}

	if (ret != 0 && signer != NULL)
	{
		free(signer);
	}

	return ret;
}

void picoquic_crypto_random(picoquic_quic * quic, void * buf, size_t len)
{
    int ret = 0;
    ptls_context_t *ctx = (ptls_context_t *)quic->tls_master_ctx;

    ctx->random_bytes(buf, len);
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
                ret = SetSignCertificate(key_file_name, ctx);
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

void picoquic_master_tlscontext_free(picoquic_quic * quic)
{
	if (quic->tls_master_ctx != NULL)
	{
		ptls_context_t *ctx = (ptls_context_t *)quic->tls_master_ctx;

		if (quic->flags&picoquic_context_server)
		{
			if (ctx->certificates.list != NULL)
			{
#if 0
				/* TODO: call proper openssl API to free the CERT */
				for (size_t i = 0; i < ctx->certificates.count; i++)
				{
					if (ctx->certificates.list[i].base != NULL)
					{
						free(ctx->certificates.list[i].base);
						ctx->certificates.list[i].base = NULL;
					}
					ctx->certificates.list[i].len = 0;
				}
#endif
				free(ctx->certificates.list);
			}

			if (ctx->verify_certificate != NULL)
			{
				free(ctx->verify_certificate);
				ctx->verify_certificate = NULL;
			}
		}
		else
		{
			if (ctx->verify_certificate != NULL)
			{
				free(ctx->verify_certificate);
				ctx->verify_certificate = NULL;
			}
		}
	}
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

/*

Using function ptls_aead_new(cipher->aead, cipher->hash, is_enc, pp->secret);
is_enc == 0 => decryption key;
is_enc != 0 => encryption key;
returns * ptls_aead_context

To use:
size_t ptls_aead_encrypt(aead_context, void* output, void* input, size_t input_len,
64bit seq, auth_data, auth_data_length);

Similar for aead_decrypt
Decrypt returns size_t_max (-1) if decryption fails, number of bytes in output otherwise

*/


#define PICOQUIC_LABEL_0RTT "EXPORTER-QUIC 0-RTT Secret"
#define PICOQUIC_LABEL_1RTT_CLIENT "EXPORTER-QUIC client 1-RTT Secret"
#define PICOQUIC_LABEL_1RTT_SERVER "EXPORTER-QUIC server 1-RTT Secret"

void picoquic_aead_free(void* aead_context)
{
    ptls_aead_free((ptls_aead_context_t *)aead_context);
}

int picoquic_setup_1RTT_aead_contexts(picoquic_cnx * cnx, int is_server)
{
    int ret = 0;
    uint8_t * secret[256]; /* secret_max */
    ptls_cipher_suite_t * cipher = ptls_get_cipher((ptls_t *) cnx->tls_ctx);

    if (cipher == NULL)
    {
        ret = -1;
    }
    else if ( cipher->hash->digest_size > sizeof(secret))
    {
        ret = -1;
    }
    else
    {
        /* Set up the encryption AEAD */
        ret = ptls_export_secret((ptls_t *)cnx->tls_ctx, secret, cipher->hash->digest_size,
            (is_server == 0)? PICOQUIC_LABEL_1RTT_CLIENT: PICOQUIC_LABEL_1RTT_SERVER,
            ptls_iovec_init(NULL, 0));

        if (ret == 0)
        {
            cnx->aead_encrypt_ctx = (void *) ptls_aead_new(cipher->aead, cipher->hash, 1, secret);

            if (cnx->aead_encrypt_ctx == NULL)
            {
                ret = -1;
            }
        }

        /* Now set up the corresponding decryption */
        if (ret == 0)
        {
            ret = ptls_export_secret((ptls_t *)cnx->tls_ctx, secret, cipher->hash->digest_size,
                (is_server != 0) ? PICOQUIC_LABEL_1RTT_CLIENT : PICOQUIC_LABEL_1RTT_SERVER,
                ptls_iovec_init(NULL, 0));
        }

        if (ret == 0)
        {
            cnx->aead_decrypt_ctx = (void *)ptls_aead_new(cipher->aead, cipher->hash, 0, secret);

            if (cnx->aead_decrypt_ctx == NULL)
            {
                ret = -1;
            }
        }
    }

    return ret;
}

size_t picoquic_aead_decrypt(picoquic_cnx *cnx, uint8_t * output, uint8_t * input, size_t input_length,
    uint64_t seq_num, uint8_t * auth_data, size_t auth_data_length)
{
    size_t decrypted = 0;

    if (cnx->aead_decrypt_ctx == NULL)
    {
        decrypted = (uint64_t)(-1ll);
    }
    else
    {
        decrypted = ptls_aead_decrypt((ptls_aead_context_t *)cnx->aead_decrypt_ctx,
            (void*)output, (const void *)input, input_length, seq_num,
            (void *)auth_data, auth_data_length);
    }

    return decrypted;
}

size_t picoquic_aead_encrypt(picoquic_cnx *cnx, uint8_t * output, uint8_t * input, size_t input_length,
    uint64_t seq_num, uint8_t * auth_data, size_t auth_data_length)
{
    size_t encrypted = ptls_aead_encrypt((ptls_aead_context_t *)cnx->aead_encrypt_ctx,
        (void*)output, (const void *)input, input_length, seq_num,
        (void *)auth_data, auth_data_length);

    return encrypted;
}

/* Input stream zero data to TLS context
 */

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
		case picoquic_state_client_init_sent:
        case picoquic_state_client_handshake_start:
        case picoquic_state_client_handshake_progress:
            /* Extract and install the client 1-RTT key */
            cnx->cnx_state = picoquic_state_client_almost_ready;
            ret = picoquic_setup_1RTT_aead_contexts(cnx, 0);
            break;
        case picoquic_state_server_init:
            /* Extract and install the server 0-RTT and 1-RTT key */
            cnx->cnx_state = picoquic_state_server_almost_ready;
            ret = picoquic_setup_1RTT_aead_contexts(cnx, 1);
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
    else if (ret == PTLS_ERROR_IN_PROGRESS && 
		(cnx->cnx_state == picoquic_state_client_init ||
			picoquic_state_client_init_sent))
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
/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

/* This module interfaces with the openssl libraries. It loads the
 * required variables and function pointers so they can be used by picoquic.
 */

#include "picotls.h"
#include "picoquic_crypto_provider_api.h"

#ifdef PTLS_WITHOUT_OPENSSL
void picoquic_openssl_load(int unload)
{
    /* Nothing to do, as the module is not loaded. */
}
#else
#include "picotls/openssl.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
/*
* Make sure that openssl is properly initialized.
*
* The OpenSSL resources are allocated on first use, and not released until the end of the
* process. The only problem is when use memory leak tracers such as valgrind. The OpenSSL
* allocations will create a large number of issues, which may hide the actual leaks that
* should be fixed. To alleviate that, the application may use an explicit call to
* a global destructor like OPENSSL_cleanup(), but normally the OpenSSL stack does it
* during the process exit.
*/
static int openssl_is_init = 0;
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER* openssl_default_provider = NULL;
#endif

static void picoquic_init_openssl()
{
    if (openssl_is_init == 0) {
        openssl_is_init = 1;
        OpenSSL_add_all_algorithms();
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
#else
        ERR_load_crypto_strings();
#if !defined(OPENSSL_NO_ENGINE)
        /* Load all compiled-in ENGINEs */
        ENGINE_load_builtin_engines();
        ENGINE_register_all_ciphers();
        ENGINE_register_all_digests();
#endif
#endif
    }
}

static void picoquic_clear_openssl()
{
    if (openssl_is_init) {
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (openssl_default_provider != NULL) {
            (void)OSSL_PROVIDER_unload(openssl_default_provider);
            openssl_default_provider = NULL;
        }
#else
#if !defined(OPENSSL_NO_ENGINE)
        /* Free allocations from engines ENGINEs */
        ENGINE_cleanup();
#endif
        ERR_free_strings();
#endif
        EVP_cleanup();
        openssl_is_init = 0;
    }
}

void picoquic_ptls_openssl_load(int unload)
{
    if (unload) {
        picoquic_clear_openssl();
    }
    else {
        picoquic_init_openssl();

        picoquic_register_ciphersuite(&ptls_openssl_aes128gcmsha256, 1);
        picoquic_register_ciphersuite(&ptls_openssl_aes256gcmsha384, 1);
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
        picoquic_register_ciphersuite(&ptls_openssl_chacha20poly1305sha256, 1);
#endif
    }
}
#endif
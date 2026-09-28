/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"

/* Same compile-time guard as picoquic_ptls_fusion.c: on platforms/builds where Fusion is
 * not compiled in, picoquic_ptls_fusion_load(int) is a no-op stub, nothing to test here. */
#if (!defined(_WINDOWS) || defined(_WINDOWS64)) && !defined(PTLS_WITHOUT_FUSION)
#include <picotls.h>
#include "picotls/fusion.h"

extern struct st_ptls_cipher_suite_t picoquic_fusion_aes128gcmsha256;
extern struct st_ptls_cipher_suite_t picoquic_fusion_aes256gcmsha384;
void picoquic_ptls_fusion_load(int unload);

/* Regression test for a bug where picoquic_ptls_fusion_load looked up the SHA256/SHA384
 * hash algorithms by their uppercase names ("SHA256"/"SHA384"), while every picotls crypto
 * provider (openssl, minicrypto, bcrypt, mbedtls) registers them lowercase ("sha256"/
 * "sha384"). Since the lookup is a case-sensitive strcmp, the fusion ciphersuites' hash
 * fields were always left NULL, so picoquic_register_ciphersuite was never called -- Fusion
 * (AES-NI hardware acceleration) was silently never usable on any CPU/platform. */
int picoquic_ptls_fusion_test(void)
{
    int ret = 0;

    /* Ensure the other providers (which actually register "sha256"/"sha384") have run
     * first, exactly as picoquic_tls_api_init_providers does in production. */
    picoquic_tls_api_init();

    picoquic_ptls_fusion_load(0);

    if (ptls_fusion_is_supported_by_cpu()) {
        if (picoquic_fusion_aes128gcmsha256.hash == NULL) {
            DBG_PRINTF("%s", "Fusion AES128-GCM-SHA256 hash was not resolved");
            ret = -1;
        }
        if (picoquic_fusion_aes256gcmsha384.hash == NULL) {
            DBG_PRINTF("%s", "Fusion AES256-GCM-SHA384 hash was not resolved");
            ret = -1;
        }
    }

    /* The unload path is documented as doing nothing; call it for coverage. */
    picoquic_ptls_fusion_load(1);

    return ret;
}
#else
int picoquic_ptls_fusion_test(void)
{
    /* Fusion is not compiled in on this platform/build -- nothing to test. */
    return 0;
}
#endif

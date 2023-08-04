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

/* This module interfaces with the PTLS "fusion" libraries. It loads the
 * required variables and function pointers so they can be used by picoquic.
 */

#include "picotls.h"
#include "picoquic_crypto_provider_api.h"

#ifdef _WINDOWS
#ifndef PTLS_WITHOUT_FUSION
 /* temporary disabling of PTLS_FUSION until memory alignment issues are fixed*/
#define PTLS_WITHOUT_FUSION
#endif
#endif

#ifdef PTLS_WITHOUT_FUSION
void picoquic_ptls_fusion_load(int unload)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(unload);
#endif
    /* Nothing to do, as the module is not loaded. */
}
#else

void picoquic_ptls_fusion_load(int unload)
{
    if (unload) {
        /* Nothing to do */
    }
    else {
        picoquic_register_ciphersuite(&picoquic_fusion_aes128gcmsha256);
        picoquic_register_ciphersuite(&picoquic_fusion_aes256gcmsha384);
    }
}
#endif
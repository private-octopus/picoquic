/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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

#ifndef H3ZERO_URL_TEMPLATE_H
#define H3ZERO_URL_TEMPLATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_h3zero_url_expression_param_t {
    char const* variable;
    size_t variable_length;
    char const* instance;
    size_t instance_length;
} h3zero_url_expression_param_t;

int h3zero_expand_template(char* buffer, size_t buffer_size, size_t* write_index, const char* url_template, const h3zero_url_expression_param_t* params, size_t nb_params);
#ifdef __cplusplus
}
#endif

#endif H3ZERO_URL_TEMPLATE_H
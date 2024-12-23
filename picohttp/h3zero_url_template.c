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

/* Simple implementation of the URL template format defined in RFC 6570.
*
* The motivation is support of the template format defined in RFC 9298,
* with examples such as:
*  https://example.org/.well-known/masque/udp/{target_host}/{target_port}/
*  https://proxy.example.org:4443/masque?h={target_host}&p={target_port}
*  https://proxy.example.org:4443/masque{?target_host,target_port}
* 
* Example translation would be:
*  https://example.org/.well-known/masque/udp/192.0.2.6/443/
*  https://proxy.example.org:4443/masque?h=example.net&p=443
*  https://proxy.example.org:4443/masque?target_host=2001%3Adb8%3A%3A42&target_port=443
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "h3zero_url_template.h"

/* Parsing of expression:
*     expression    =  "{" [ operator ] variable-list "}"
*     operator      =  op-level2 / op-level3 / op-reserve
*     op-level2     =  "+" / "#"
*     op-level3     =  "." / "/" / ";" / "?" / "&"
*     op-reserve    =  "=" / "," / "!" / "@" / "|"
* 
*     variable-list =  varspec *( "," varspec )
*     varspec       =  varname [ modifier-level4 ]
*     varname       =  varchar *( ["."] varchar )
*     varchar       =  ALPHA / DIGIT / "_" / pct-encoded
*/

typedef enum {
    modality_none,
    modality_middle,
    modality_prefix,
    modality_suffix,
    modality_form
} modality_enum;

static int parse_modality(const char* expression, size_t* parse_index, char* modality)
{
    int ret = 0;
    char c = expression[*parse_index];

    *modality = 0;
    /* Check whether there is a modality */
    switch (c) {
    case '+':
    case '.':
    case '/':
    case ';':
    case '&':
    case '?':
        *modality = c;
        *parse_index += 1;
        break;
    case '#':
    case '=':
    case ',':
    case '!':
    case '@':
    case '|':
        ret = -1;
        break;
    default:
        *modality = 0;
        break;
    }
    return ret;
}

static size_t h3zero_parse_expression_variable(const char* expression, size_t* parse_index, int *has_multiplier, int * prefix)
{
    size_t var_length = 0;
    int has_prefix = 0;
    char c;

    *prefix = -1;
    *has_multiplier = 0;
    while ((c=expression[*parse_index]) != 0) {
        if (c == '}' || c == ',') {
            break;
        }
        *parse_index += 1;
        if (c == '*') {
            *has_multiplier = 1;
            break;
        }
        else if (c == ':') {
            has_prefix = 1;
            break;
        }
        else {
            var_length += 1;
        }
    }

    if (has_prefix) {
        *prefix = 0;
        while ((c = expression[*parse_index]) != 0) {
            if (c >= '0' && c <= '9') {
                *parse_index += 1;
                *prefix *= 10;
                *prefix += c - '0';
            }
            else {
                break;
            }
        }
    }

    return var_length;
}


static int h3zero_expand_char(char* buffer, size_t buffer_size, size_t* write_index, char c)
{
    int ret = 0;
    if (*write_index < buffer_size) {
        buffer[*write_index] = c;
        *write_index += 1;
    }
    else {
        ret = -1;
    }
    return ret;
}

static int h3zero_expand_text(char* buffer, size_t buffer_size, size_t* write_index, int prefix, char const* text, size_t text_length)
{
    int ret = 0;
    int written = 0;

    for (size_t i = 0; i < text_length && ret == 0 && (prefix <= 0 || written < prefix); i++) {
        char c = text[i];

        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' ||
            c == '.' ||
            c == '_' ||
            c == '~') {
            ret = h3zero_expand_char(buffer, buffer_size, write_index, c);

            written += 1;
        }
        else if (*write_index + 3 < buffer_size) {
            char c1 = '0' + ((c >> 4) & 0xf);
            char c2 = '0' + (c & 0xf);
            if (c1 > '9') {
                c1 += 'A' - '9';
            }
            if (c2 > '9') {
                c2 += 'A' - '9';
            }

            buffer[*write_index] = '%';
            *write_index += 1;
            buffer[*write_index] = c1;
            *write_index += 1;
            buffer[*write_index] = c2;
            *write_index += 1;

            written += 3;
        }
        else {
            ret = -1;
        }
    }

    return ret;
}

static int h3zero_expand_variable_tag(char* buffer, size_t buffer_size, size_t* write_index, char separator, char const* variable, size_t variable_length)
{
    int ret = 0;

    if (*write_index + variable_length + 2 >= buffer_size) {
        ret = 1;
    }
    else {
        buffer[*write_index] = separator;
        *write_index += 1;
        memcpy(&buffer[*write_index], variable, variable_length);
        *write_index += variable_length;
        buffer[*write_index] = '=';
        *write_index += 1;
    }

    return ret;
}

static int h3zero_expand_expression_variable(char* buffer, size_t buffer_size, size_t* write_index, char modality,
    int is_first, int has_multiplier, int prefix, char const* variable, size_t variable_length, 
    const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret = 0;
    int nb_match = 0;

    for (size_t i_param = 0; i_param < nb_params && ret == 0; i_param++) {
        if (params[i_param].variable_length == variable_length &&
            memcmp(variable, params[i_param].variable, variable_length) == 0) {
            char separator = 0;
            int has_name = 0;

            switch (modality) {
            case '.':
                separator = modality;
                break;
            case '/':
                if (nb_match == 0 || has_multiplier) {
                    separator = modality;
                }
                else {
                    separator = ',';
                }
                break;
            case '&':
            case ';':
                if (nb_match == 0 || has_multiplier) {
                    separator = modality;
                    has_name = 1;
                }
                else {
                    separator = ',';
                }
                break;
            case '?':
                if (is_first && nb_match == 0) {
                    separator = modality;
                    has_name = 1;
                }
                else if (nb_match == 0 || has_multiplier) {
                    separator = '&';
                    has_name = 1;
                }
                else {
                    separator = ',';
                }
                break;
            default:
                if (!is_first || nb_match > 0) {
                    separator = ',';
                }
                break;
            }
            if (separator != 0) {
                if (has_name) {
                    ret = h3zero_expand_variable_tag(buffer, buffer_size, write_index, separator, variable, variable_length);
                }
                else {
                    ret = h3zero_expand_char(buffer, buffer_size, write_index, separator);
                }
            }
            if (ret == 0) {
                /* Copy the variable to the buffer. Escape illegal characters,
                 * enforce "prefix" limit */
                ret = h3zero_expand_text(buffer, buffer_size, write_index, prefix, params[i_param].instance, params[i_param].instance_length);
                nb_match += 1;
            }
        }
    }
    return ret;
}

/* h3zero_expand_expression:
 * assume that the initial "{" is already parsed. 
 */
int h3zero_expand_template_expression(char* buffer, size_t buffer_size, size_t * write_index, const char* expression, size_t* parse_index, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret;
    char modality;
    size_t variable_index;
    size_t variable_length;
    int prefix;
    int has_multiplier;
    int is_finished = 0;
    int is_first = 1;
    size_t first_index = *write_index;
    char c;

    ret = parse_modality(expression, parse_index, &modality);

    while (ret == 0 && (c = expression[*parse_index]) != 0) {
        /* Check for end of expression */
        if (c == '}') {
            /* end of expression */
            *parse_index += 1;
            is_finished = 1;
            break;
        }
        if (!is_first) {
            if (c == ',') {
                *parse_index += 1;
            }
            else {
                ret = -1;
                break;
            }
        }
        /* find the next variable in the list */
        variable_index = *parse_index;
        variable_length = h3zero_parse_expression_variable(expression, parse_index, &has_multiplier, &prefix);
        if (prefix == 0 || prefix > 10000 || variable_length == 0) {
            ret = -1;
        }
        else {
            /* process the variable according to modality */
            ret = h3zero_expand_expression_variable(buffer, buffer_size, write_index, modality, 
                first_index == *write_index, has_multiplier,
                prefix, &expression[variable_index], variable_length, params, nb_params);
            is_first = 0;
        }
    }
    if (!is_finished) {
        ret = -1;
    }
    return ret;
}

int h3zero_expand_template(char* buffer, size_t buffer_size, size_t* write_index, const char* url_template, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret = 0;
    size_t parse_index = 0;
    char c = 0;

    *write_index = 0;

    if (buffer_size == 0) {
        ret = -1;
    }
    else {
        while ((c = url_template[parse_index]) != 0 && ret == 0) {
            parse_index++;
            if (c == '{') {
                ret = h3zero_expand_template_expression(buffer, buffer_size, write_index,
                    url_template, &parse_index, params, nb_params);
            }
            else if (*write_index < buffer_size) {
                buffer[*write_index] = c;
                *write_index += 1;
            }
            else {
                /* buffer is too short */
                ret = -1;
            }
        }
        if (*write_index < buffer_size) {
            buffer[*write_index] = 0;
        }
        else {
            ret = -1;
            buffer[buffer_size - 1] = 0;
        }
    }
    return ret;
}

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

int parse_expression_modality(char* template, size_t* parse_index, char* moda_char, modality_enum *moda_mode)
{
    int ret = 0;
    char c = template[*parse_index];
    int is_parsed = 1;
    *moda_char = c;
    *moda_mode = modality_none;
    /* Check whether there is a modality */
    switch (c) {
    case '+':
    case '#':
        *moda_mode = modality_none;
        break;
    case '.':
        *moda_mode = modality_middle;
        break;
    case '/':
    case ';':
    case '&':
        *moda_char = 'c';
        *moda_mode = modality_prefix;
        break;
    case '?':
        *moda_char = '&';
        *moda_mode = modality_form;
        break;
    case '=':
    case ',':
    case '!':
    case '@':
    case '|':
        ret = -1;
        break;
    default:
        *moda_char = 0;
        break;
    }
    if (ret == 0 && *moda_char != 0) {
        *parse_index++;
    }
    return ret;
}

static int h3zero_parse_expression_variable()
{

}


static int h3zero_expand_expression_variable(char* buffer, size_t buffer_size, size_t* write_index, char modality, int* is_first, char const* variable, size_t variable_length, h3zero_url_expression_param_t* params, size_t nb_params)
{
    /* if modality is ?, add the name of the variable and the equal sign */
    /* write the matching value */
    /* if more than one value, repeat the separators, etc. */
    /* if no matching value, process as empty */
}

int h3zero_expand_template_expression(char* buffer, size_t buffer_size, size_t * write_index, const char* template, size_t* parse_index, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    char moda_char;
    modality_enum moda_mode;
    int ret = parse_modality(template, parse_index, &moda_char, modality_enum * moda_mode);
    /* find the next variable in the list */
    /* process the variable according to modality */
    /* if present, skip the comma and loop */
    /* expect a final '}' or complain. */
    return ret;
}


int h3zero_expand_template(char* buffer, size_t buffer_size, size_t* write_index, const char* template, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret = 0;
    size_t parse_index = 0;
    char c = 0;

    *write_index = 0;

    if (buffer_size == 0) {
        ret = -1;
    }
    else {
        while ((c = template[parse_index]) != 0 && ret == 0) {
            parse_index++;
            if (c == '{') {
                size_t expression_length = 0;
                ret = h3zero_expand_expression(buffer, buffer_length, &write_index,
                    template, &parse_index, params, nb_params);
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

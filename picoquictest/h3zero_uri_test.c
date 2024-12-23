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

#include <string.h>
#include <stdlib.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "h3zero_uri.h"
#include "h3zero_url_template.h"

#define abempty_one_char '/'
#define abempty_one_name '/','e','x','a','m','p','l','e'
#define abempty_two_names abempty_one_name,abempty_one_name
#define i_val_1 '1'
#define i_val_n '1','2','3','4','5','6','7','8','9'
#define i_val_nx '1','%','3','2','3','4','5','6','7','8','9'
#define i_val_bad '1','%','a','b','3','4','5','6','7','8','9'
#define i_val_overflow i_val_n , i_val_n , i_val_n
#define i_val_bad2 '1','2','3','4','5','6','7','%','9'
#define i_val_bad3 '1','2','3','4','5','6','7','%'
#define s_val_1 'a'
#define s_val_8 'a','b','c','d','e','f','g','0'
#define s_val_x 'a','b','c','d','e','f','g','%','3','0'
#define s_val_bad 'a','b','c','d','e','f','g','%','3'
#define s_val_too_long s_val_8,'x'
#define name_int 'i','n','t'
#define name_txt 't','x','t'
#define name_other 'o','t','h','e','r'

char const str_1[] = { s_val_1 };
char const str_8[] = { s_val_8 };

char const param_int[] = { name_int };
char const param_txt[] = { name_txt };

char const path01[] = { abempty_one_char };
char const path02[] = { abempty_one_char, '?' };
char const path03[] = { abempty_one_char, '?', name_int, '=', i_val_1 };
char const path04[] = { abempty_one_char, '?', name_txt, '=', s_val_1 };
char const path05[] = { abempty_one_char, '?', name_txt, '=', s_val_1, '&', name_int, '=', i_val_1};
char const path06[] = { abempty_one_char, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_1 };
char const path07[] = { abempty_one_char, '?', name_int, '=', i_val_n, '&', name_txt, '=', s_val_8 };
char const path08[] = { abempty_one_char, '?', name_int, '=', i_val_nx, '&', name_txt, '=', s_val_x };
char const path09[] = { abempty_one_char, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_bad };
char const path10[] = { abempty_one_char, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_too_long };
char const path11[] = { abempty_one_char, '?', name_int, '=', i_val_bad, '&', name_txt, '=', s_val_1 };
char const path12[] = { abempty_one_char, '?', name_int, '=', i_val_bad2, '&', name_txt, '=', s_val_1 };
char const path13[] = { abempty_one_char, '?', name_int, '=', i_val_bad3, '&', name_txt, '=', s_val_1 };
char const path14[] = { abempty_one_char, '?', name_int, '=', i_val_overflow, '&', name_txt, '=', s_val_1 };
char const path15[] = { abempty_one_name, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_1 };
char const path16[] = { abempty_two_names, '?', name_int, '=', i_val_1, '&',  name_txt, '=', s_val_1 };
char const path17[] = { abempty_two_names, '?', name_int, '=', i_val_1, '&', name_other, '=', i_val_1, '&', name_txt, '=', s_val_1 };
char const path18[] = { abempty_two_names, '?', name_int, '=', i_val_1, '&', name_other, '&', name_txt, '=', s_val_1 };

typedef struct st_h3zero_uri_path_test_case_t {
    const uint8_t* path;
    size_t path_length;
    uint64_t val_int;
    const uint8_t * text;
    size_t text_len;
    int ret;
} h3zero_uri_path_test_case_t;

#define URI_PATH_TEST(p, i, t, r) { (const uint8_t*)p, sizeof(p), i, (const uint8_t *)t, sizeof(t), r }

h3zero_uri_path_test_case_t uri_test_cases[] = {
    { NULL, 0, 0, NULL, 0 },
    { (const uint8_t*)path01, sizeof(path01), 0, NULL, 0, 0 },
    { (const uint8_t*)path02, sizeof(path02), 0, NULL, 0, 0 },
    { (const uint8_t*)path03, sizeof(path03), 1, NULL, 0, 0 },
    URI_PATH_TEST(path04, 0, str_1, 0),
    URI_PATH_TEST(path05, 1, str_1, 0),
    URI_PATH_TEST(path06, 1, str_1, 0),
    URI_PATH_TEST(path07, 123456789, str_8, 0),
    URI_PATH_TEST(path08, 123456789, str_8, 0),
    URI_PATH_TEST(path09, 1, str_8, -1),
    URI_PATH_TEST(path10, 1, str_8, -1),
    URI_PATH_TEST(path11, 0, str_1, -1),
    URI_PATH_TEST(path12, 0, str_1, -1),
    URI_PATH_TEST(path13, 0, str_1, -1),
    URI_PATH_TEST(path14, 0, str_1, -1),
    URI_PATH_TEST(path15, 1, str_1, 0),
    URI_PATH_TEST(path16, 1, str_1, 0),
    URI_PATH_TEST(path17, 1, str_1, 0),
    URI_PATH_TEST(path18, 1, str_1, 0)
};

size_t nb_test_cases = sizeof(uri_test_cases) / sizeof(h3zero_uri_path_test_case_t);

int h3zero_uri_test_one(h3zero_uri_path_test_case_t* test_case)
{
    int ret = 0;
    int t_ret = 0;
    uint64_t val_int = 0;
    uint8_t text[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    size_t text_len = 0;
    size_t query_offset = h3zero_query_offset(test_case->path, test_case->path_length);
    if (query_offset < test_case->path_length) {
        const uint8_t* queries = test_case->path + query_offset;
        size_t queries_length = test_case->path_length - query_offset;

        t_ret = h3zero_query_parameter_number(queries, queries_length, param_int, sizeof(param_int), &val_int, 0);
        if (t_ret == 0){
            t_ret = h3zero_query_parameter_string(queries, queries_length, param_txt, sizeof(param_txt), text, sizeof(text), &text_len);
        }
    }

    if (t_ret != test_case->ret) {
        DBG_PRINTF("Return: %d vs %d", t_ret, test_case->ret);
        ret = -1;
    }
    else if (t_ret == 0) {
        if (val_int != test_case->val_int) {
            DBG_PRINTF("val_int: %" PRIu64 " vs %" PRIu64, val_int, test_case->val_int);
            ret = -1;
        }
        else if (text_len != test_case->text_len) {
            DBG_PRINTF("text_len: %zu vs %zu", text_len, test_case->text_len);
            ret = -1;
        }
        else if (text_len > 0 && memcmp(text, test_case->text, text_len) != 0) {
            DBG_PRINTF("text_value length %zu do not match", text_len);
            ret = -1;
        }
    }
    return ret;
}

int h3zero_uri_test()
{
    int ret = 0;
    for (size_t i = 0; i < nb_test_cases; i++) {
        if ((ret = h3zero_uri_test_one(&uri_test_cases[i])) != 0) {
            DBG_PRINTF("Failure for uri test case %zu", i);
            break;
        }
    }
    return ret;
}

/* Tests of URL template 
 */

typedef struct st_template_test_var_t {
    char const* var_name;
    char const* instances[4];
} template_test_var_t;

template_test_var_t tt_vars[] = {
    { "count", {"one", "two", "three", NULL }},
    { "dom", {"example", "com", NULL }},
    { "dub", {"me/too", NULL }},
    { "hello", {"Hello World!", NULL }},
    { "half", {"50%", NULL }},
    { "var", {"value", NULL }},
    { "who", {"fred", NULL }},
    { "base", {"http://example.com/home/", NULL }},
    { "path", {"/foo/bar", NULL }},
    { "list", {"red", "green", "blue", NULL }},
    { "empty", {"", NULL}},
    { "undef", {NULL}},
    { "x", { "1024", NULL}},
    { "y", { "768", NULL}}
};

typedef struct st_expansion_test_case_t {
    char const* expression;
    char const* expansion;
} template_test_case_t;

template_test_case_t template_test_cases[] = {
    { "{count}",   "one,two,three"},
    { "{count*}",  "one,two,three"},
    { "{/count}",  "/one,two,three"},
    { "{/count*}", "/one/two/three"},
    { "{;count}",  ";count=one,two,three"},
    { "{;count*}", ";count=one;count=two;count=three"},
    { "{?count}",  "?count=one,two,three"},
    { "{?count*}", "?count=one&count=two&count=three"},
    { "{&count*}", "&count=one&count=two&count=three"},
    { "{.dom*}",   ".example.com" },
    {"{var}", "value"},
    {"{hello}", "Hello%20World%21"},
    {"{half}", "50%25"},
    {"O{empty}X", "OX"},
    {"O{undef}X", "OX"},
    {"{x,y}", "1024,768"},
    {"{x,hello,y}", "1024,Hello%20World%21,768"},
    {"?{x,empty}", "?1024,"},
    {"?{x,undef}", "?1024"},
    {"?{undef,y}", "?768"},
    {"{var:3}", "val"},
    {"{var:30}", "value"},
    {"{list}", "red,green,blue"},
    {"{list*}", "red,green,blue"}
};

template_test_case_t template_error_cases[] = {
    { "{count",   "one,two,three"}, /* Missing final } */
    { "{count**}",   "one,two,three"}, /* unexpected * } */
    { "{count:0}",   "one,two,three"}, /* zero length prefix */
    { "{count:abcd}",   "one,two,three"}, /* non number prefix */
    { "{}",   "one,two,three"}, /* zero length variable  */
    { "{:123}",   "one,two,three"}, /* zero length variable */
    { "{a,count",   "one,two,three"}, /* Missing final after 2  */
    { "{a,count**}",   "one,two,three"}, /* unexpected * on second variable */
    { "{a,count:0}",   "one,two,three"}, /* zero length prefix on second variable */
    { "{a,count:abcd}",   "one,two,three"}, /* non number prefix on second variable */
    { "{a,}",   "one,two,three"}, /* zero length second variable */
    { "{a,:123}",   "one,two,three"}, /* zero length second variable */
};

size_t template_test_get_params(const template_test_var_t* table, size_t nb_lines, h3zero_url_expression_param_t* params, size_t params_max)
{
    size_t nb_params = 0;
    size_t n_line = 0;
    size_t n_instance = 0;

    while (n_line < nb_lines && nb_params < params_max) {
        if (table[n_line].instances[n_instance] == NULL) {
            n_line++;
            n_instance = 0;
        }
        else {
            params[nb_params].variable = table[n_line].var_name;
            params[nb_params].variable_length = strlen(params[nb_params].variable);
            params[nb_params].instance = table[n_line].instances[n_instance];
            params[nb_params].instance_length = strlen(params[nb_params].instance);
            n_instance++;
            nb_params++;
        }
    }
    return nb_params;
}

static int template_test_one_template(const template_test_case_t* test_case, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    char expanded[256];
    size_t write_index = 0;
    int ret = h3zero_expand_template(expanded, sizeof(expanded), &write_index, test_case->expression, params, nb_params);

    if (ret == 0) {
        if (write_index != strlen(test_case->expansion)) {
            ret = -1;
        }
        else {
            expanded[write_index] = 0;
            if (strcmp(expanded, test_case->expansion) != 0) {
                ret = -1;
            }
        }
    }
    return ret;
}

static int template_test_short_length(const template_test_case_t* test_case, const h3zero_url_expression_param_t* params, size_t nb_params, size_t short_length)
{
    int ret = 0;
    char expanded[256];
    size_t write_index = 0;

    if (short_length > sizeof(expanded)) {
        ret = -1;
    }
    else if (h3zero_expand_template(expanded, short_length, &write_index, test_case->expression, params, nb_params) == 0) {
        ret = -1;
    }

    return ret;
}

static int template_test_templates(const template_test_case_t* test_cases, size_t nb_cases, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret = 0;

    for (size_t n_case = 0; n_case < nb_cases && ret == 0; n_case++) {
        ret = template_test_one_template(&test_cases[n_case], params, nb_params);
    }

    return ret;
}

static int template_test_error_templates(const template_test_case_t* test_cases, size_t nb_cases, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret = 0;

    for (size_t n_case = 0; n_case < nb_cases && ret == 0; n_case++) {
        if (template_test_one_template(&test_cases[n_case], params, nb_params) == 0) {
            ret = -1;
        }
    }

    return ret;
}

static int template_test_error_length(const template_test_case_t* test_cases, size_t nb_cases, const h3zero_url_expression_param_t* params, size_t nb_params)
{
    int ret = 0;

    for (size_t n_case = 0; n_case < nb_cases && ret == 0; n_case++) {
        for (size_t short_length = 0; short_length <= strlen(test_cases[n_case].expansion); short_length++) {
            ret = template_test_short_length(&test_cases[n_case], params, nb_params, short_length);
        }
    }

    return ret;
}

int h3zero_url_template_test()
{
    int ret = 0;
    /* First, build a list of parameters */
    h3zero_url_expression_param_t params[32] = { 0 };
    size_t nb_params = template_test_get_params(tt_vars,
        sizeof(tt_vars) / sizeof(template_test_var_t),
        params, 32);
    if (nb_params != 18) {
        ret = -1;
    }

    if (ret == 0) {
        ret = template_test_templates(template_test_cases, sizeof(template_test_cases) / sizeof(template_test_case_t), params, nb_params);
    }

    if (ret == 0) {
        ret = template_test_error_templates(template_error_cases, sizeof(template_error_cases) / sizeof(template_test_case_t), params, nb_params);
    }

    if (ret == 0) {
        ret = template_test_error_length(template_test_cases, sizeof(template_test_cases) / sizeof(template_test_case_t), params, nb_params);
    }

    return ret;
}
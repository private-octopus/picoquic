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

#include <stdio.h>
#include <string.h>
#include "../picoquic/picoquic.h"
#include "../picoquictest/picoquictest.h"

typedef struct st_picoquic_test_def_t {
    char const * test_name;
    int(*test_fn)();
} picoquic_test_def_t;

static picoquic_test_def_t test_table[] = {
    { "picohash", picohash_test },
    { "cnxcreation", cnxcreation_test },
    { "parseheader", parseheadertest },
    { "pn2pn64", pn2pn64test },
    { "intformat", intformattest},
    {"fnv1a", fnv1atest},
    { "sack", sacktest },
    { "float16", float16test },
    { "StreamZeroFrame", StreamZeroFrameTest },
    { "sendack", sendacktest },
    { "tls_api", tls_api_test },
    {"tls_api_version_negotiation", tls_api_version_negotiation_test},
    { "transport_param", transport_param_test },
    { "tls_api_sni", tls_api_sni_test },
    { "tls_api_alpn", tls_api_alpn_test },
    { "tls_api_wrong_alpn", tls_api_wrong_alpn_test },
    { "tls_api_oneway_stream", tls_api_oneway_stream_test },
    { "tls_api_q_and_r_stream", tls_api_q_and_r_stream_test },
    { "tls_api_q2_and_r2_stream", tls_api_q2_and_r2_stream_test },
    { "tls_api_server_reset", tls_api_server_reset_test },
    { "tls_api_bad_server_reset", tls_api_bad_server_reset_test },
    { "sim_link", sim_link_test },
    { "tls_api_very_long_stream", tls_api_very_long_stream_test },
    { "tls_api_very_long_max", tls_api_very_long_max_test },
    { "tls_api_very_long_with_err", tls_api_very_long_with_err_test },
    { "tls_api_very_long_congestion", tls_api_very_long_congestion_test },
    { "http0dot9", http0dot9_test },
    { "hrr", tls_api_hrr_test }
};

static size_t nb_tests = sizeof(test_table) / sizeof(picoquic_test_def_t);

static int do_one_test(size_t i, FILE * F)
{
    int ret = 0;

    if (i >= nb_tests)
    {
        fprintf(F, "Invalid test number %zu\n", i);
        ret = -1;
    }
    else
    {
        fprintf(F, "Starting test number %zu, %s\n", i, test_table[i].test_name);
        ret = test_table[i].test_fn();
        if (ret == 0)
        {
            fprintf(F, "    Success.\n");
        }
        else
        {
            fprintf(F, "    Fails, error: %d.\n", ret);
        }
    }

    return ret;
}

int main(int argc, char ** argv)
{
    int ret = 0;
    int arg_err = 0;
    int nb_test_tried = 0;
    int nb_test_failed = 0;

    if (argc <= 1)
    {
        for (size_t i = 0; i < nb_tests; i++)
        {
            nb_test_tried++;
            if (do_one_test(i, stdout) != 0)
            {
                nb_test_failed++;
                ret = -1;
            }
        }
    }
    else
    {
        for (int arg_num = 1; arg_num < argc; arg_num++)
        {
            int tried = 0;

            for (size_t i = 0; i < nb_tests; i++)
            {
                if (strcmp(argv[arg_num], test_table[i].test_name) == 0)
                {
                    tried = 1;
                    nb_test_tried++;
                    if (do_one_test(i, stdout) != 0)
                    {
                        nb_test_failed++;
                        ret = -1;
                    }
                    break;
                }
            }

            if (tried == 0)
            {
                fprintf(stderr, "Incorrect test name: %s\n", argv[arg_num]);
                arg_err++;
                ret = -1;
                break;
            }
        }
    }

    if (nb_test_tried > 1)
    {
        fprintf(stdout, "Tried %d tests, %d fail%s.\n", nb_test_tried,
            nb_test_failed, (nb_test_failed > 1) ? "" : "s");
    }

    if (arg_err != 0)
    {
        fprintf(stderr, "\nUsage: %s [test1 [test2 ..[testN]]]\n\n", argv[0]);
        fprintf(stderr, "Valid test names are: \n");
        for (size_t x = 0; x < nb_tests; x++)
        {
            fprintf(stderr, "    ");

            for (int j = 0; j < 4 && x < nb_tests; j++, x++)
            {
                fprintf(stderr, "%s, ", test_table[x].test_name);
            }
            fprintf(stderr, "\n");
        }
    }

    return (ret);
}

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

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#include <picotls.h>
#include "picoquic_crypto_provider_api.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AEGISPERF_SAMPLES_MAX 64

typedef struct st_aegis_perf_suite_t {
    char const* label;
    int cipher_suite_id;
} aegis_perf_suite_t;

typedef struct st_aegis_perf_config_t {
    size_t samples;
    size_t micro_iters;
    size_t micro_bytes;
    size_t transfer_iters;
    size_t transfer_bytes;
} aegis_perf_config_t;

typedef struct st_aegis_perf_stats_t {
    double mean;
    double median;
    double min;
    double max;
} aegis_perf_stats_t;

static aegis_perf_suite_t aegis_perf_suites[] = {
    { "TLS_AES_128_GCM_SHA256", PICOQUIC_AES_128_GCM_SHA256 },
    { "TLS_AES_256_GCM_SHA384", PICOQUIC_AES_256_GCM_SHA384 },
    { "TLS_CHACHA20_POLY1305_SHA256", PICOQUIC_CHACHA20_POLY1305_SHA256 },
    { "TLS_AEGIS_128L_SHA256", PICOQUIC_AEGIS_128L_SHA256 },
    { "TLS_AEGIS_256_SHA512", PICOQUIC_AEGIS_256_SHA512 }
};

static uint64_t aegis_perf_now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static int aegis_perf_double_compare(const void* a, const void* b)
{
    double va = *(double const*)a;
    double vb = *(double const*)b;
    return (va > vb) - (va < vb);
}

static aegis_perf_stats_t aegis_perf_get_stats(double* values, size_t count)
{
    aegis_perf_stats_t stats = { 0, 0, 0, 0 };

    if (count > 0) {
        qsort(values, count, sizeof(double), aegis_perf_double_compare);
        stats.min = values[0];
        stats.max = values[count - 1];
        stats.median = (count & 1) ? values[count / 2] :
            (values[(count / 2) - 1] + values[count / 2]) / 2.0;

        for (size_t i = 0; i < count; i++) {
            stats.mean += values[i];
        }
        stats.mean /= (double)count;
    }

    return stats;
}

static int aegis_perf_parse_size(char const* text, size_t* value)
{
    char* end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    int ret = (end == text) ? -1 : 0;

    if (ret == 0) {
        if (*end == 'k' || *end == 'K') {
            parsed *= 1024ull;
            end++;
        }
        else if (*end == 'm' || *end == 'M') {
            parsed *= 1024ull * 1024ull;
            end++;
        }

        if (*end != 0) {
            ret = -1;
        }
        else {
            *value = (size_t)parsed;
        }
    }

    return ret;
}

static int aegis_perf_parse_args(int argc, char** argv, aegis_perf_config_t* config)
{
    int ret = 0;

    for (int i = 1; ret == 0 && i < argc; i++) {
        if (i + 1 >= argc) {
            ret = -1;
        }
        else if (strcmp(argv[i], "--samples") == 0) {
            ret = aegis_perf_parse_size(argv[++i], &config->samples);
        }
        else if (strcmp(argv[i], "--micro-iters") == 0) {
            ret = aegis_perf_parse_size(argv[++i], &config->micro_iters);
        }
        else if (strcmp(argv[i], "--micro-bytes") == 0) {
            ret = aegis_perf_parse_size(argv[++i], &config->micro_bytes);
        }
        else if (strcmp(argv[i], "--transfer-iters") == 0) {
            ret = aegis_perf_parse_size(argv[++i], &config->transfer_iters);
        }
        else if (strcmp(argv[i], "--transfer-bytes") == 0) {
            ret = aegis_perf_parse_size(argv[++i], &config->transfer_bytes);
        }
        else {
            ret = -1;
        }
    }

    if (config->samples == 0 || config->samples > AEGISPERF_SAMPLES_MAX ||
        config->micro_iters == 0 || config->micro_bytes == 0 ||
        config->transfer_iters == 0 || config->transfer_bytes == 0) {
        ret = -1;
    }

    return ret;
}

static void aegis_perf_usage(char const* argv0)
{
    fprintf(stderr, "Usage: %s [--samples n] [--micro-iters n] [--micro-bytes n] [--transfer-iters n] [--transfer-bytes n]\n", argv0);
}

static int aegis_perf_micro_one(aegis_perf_suite_t* suite_spec, aegis_perf_config_t* config)
{
    ptls_cipher_suite_t* suite = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(suite_spec->cipher_suite_id, 0);
    double mbps[AEGISPERF_SAMPLES_MAX];
    double usec[AEGISPERF_SAMPLES_MAX];
    uint8_t* input = NULL;
    uint8_t* output = NULL;
    uint8_t aad[32] = { 0 };
    uint8_t key[64] = { 0 };
    uint8_t iv[64] = { 0 };
    uint8_t checksum = 0;
    int ret = 0;

    if (suite == NULL) {
        printf("micro,%s,0x%04x,0,0,0,0,0,0,0,0,0,0,0,unavailable\n",
            suite_spec->label, suite_spec->cipher_suite_id);
        return 0;
    }

    input = (uint8_t*)malloc(config->micro_bytes);
    output = (uint8_t*)malloc(config->micro_bytes + suite->aead->tag_size);

    if (input == NULL || output == NULL) {
        ret = -1;
    }

    for (size_t i = 0; ret == 0 && i < config->micro_bytes; i++) {
        input[i] = (uint8_t)i;
    }

    for (size_t i = 0; ret == 0 && i < config->samples; i++) {
        ptls_aead_context_t* aead = ptls_aead_new_direct(suite->aead, 1, key, iv);
        uint64_t start_ns;
        uint64_t elapsed_ns;

        if (aead == NULL) {
            ret = -1;
            break;
        }

        start_ns = aegis_perf_now_ns();
        for (size_t j = 0; j < config->micro_iters; j++) {
            (void)ptls_aead_encrypt(aead, output, input, config->micro_bytes, (uint64_t)j, aad, sizeof(aad));
            checksum ^= output[j % config->micro_bytes];
        }
        elapsed_ns = aegis_perf_now_ns() - start_ns;
        ptls_aead_free(aead);

        if (elapsed_ns == 0) {
            elapsed_ns = 1;
        }
        usec[i] = (double)elapsed_ns / 1000.0;
        mbps[i] = ((double)config->micro_bytes * (double)config->micro_iters) / ((double)elapsed_ns / 1000000000.0) / 1000000.0;
    }

    if (ret == 0) {
        aegis_perf_stats_t mbps_stats = aegis_perf_get_stats(mbps, config->samples);
        aegis_perf_stats_t usec_stats = aegis_perf_get_stats(usec, config->samples);

        printf("micro,%s,0x%04x,%zu,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,ok\n",
            suite_spec->label, suite_spec->cipher_suite_id, config->micro_bytes, config->micro_iters,
            config->samples, mbps_stats.mean, mbps_stats.median, mbps_stats.min, mbps_stats.max,
            usec_stats.mean, usec_stats.median, usec_stats.min, usec_stats.max);
        fflush(stdout);
    }

    if (input != NULL) {
        free(input);
    }
    if (output != NULL) {
        free(output);
    }

    return ret == 0 ? (int)checksum & 0 : ret;
}

static int aegis_perf_transfer_sample(aegis_perf_suite_t* suite_spec, size_t transfer_bytes, double* mbps, double* usec)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    test_api_stream_desc_t scenario[1] = { { 4, 0, 0, 0 } };
    uint64_t simulated_time = 0;
    uint64_t start_ns;
    uint64_t elapsed_ns;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
        &simulated_time, NULL, NULL, 0, 1, 0);

    scenario[0].q_len = transfer_bytes;

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0 && picoquic_set_cipher_suite(test_ctx->qclient, suite_spec->cipher_suite_id) != 0) {
        ret = -1;
    }

    if (ret == 0 && picoquic_set_cipher_suite(test_ctx->qserver, suite_spec->cipher_suite_id) != 0) {
        ret = -1;
    }

    start_ns = aegis_perf_now_ns();

    if (ret == 0) {
        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0, 0);
    }

    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, sizeof(scenario));
    }

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &test_ctx->loss_mask_default, &simulated_time, 0);
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 0);
    }

    elapsed_ns = aegis_perf_now_ns() - start_ns;

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    if (ret == 0) {
        if (elapsed_ns == 0) {
            elapsed_ns = 1;
        }
        *usec = (double)elapsed_ns / 1000.0;
        *mbps = (double)transfer_bytes / ((double)elapsed_ns / 1000000000.0) / 1000000.0;
    }

    return ret;
}

static int aegis_perf_transfer_sample_repeat(aegis_perf_suite_t* suite_spec, size_t transfer_bytes,
    size_t transfer_iters, double* mbps, double* usec)
{
    double total_mbps = 0;
    double total_usec = 0;
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < transfer_iters; i++) {
        double sample_mbps = 0;
        double sample_usec = 0;

        ret = aegis_perf_transfer_sample(suite_spec, transfer_bytes, &sample_mbps, &sample_usec);
        total_usec += sample_usec;
    }

    if (ret == 0) {
        total_mbps = ((double)transfer_bytes * (double)transfer_iters) / (total_usec / 1000000.0) / 1000000.0;
        *usec = total_usec;
        *mbps = total_mbps;
    }

    return ret;
}

static int aegis_perf_transfer_one(aegis_perf_suite_t* suite_spec, aegis_perf_config_t* config)
{
    ptls_cipher_suite_t* suite = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(suite_spec->cipher_suite_id, 0);
    double mbps[AEGISPERF_SAMPLES_MAX];
    double usec[AEGISPERF_SAMPLES_MAX];
    int ret = 0;

    if (suite == NULL) {
        printf("transfer,%s,0x%04x,0,0,0,0,0,0,0,0,0,0,0,unavailable\n",
            suite_spec->label, suite_spec->cipher_suite_id);
        return 0;
    }

    for (size_t i = 0; ret == 0 && i < config->samples; i++) {
        ret = aegis_perf_transfer_sample_repeat(suite_spec, config->transfer_bytes,
            config->transfer_iters, &mbps[i], &usec[i]);
    }

    if (ret == 0) {
        aegis_perf_stats_t mbps_stats = aegis_perf_get_stats(mbps, config->samples);
        aegis_perf_stats_t usec_stats = aegis_perf_get_stats(usec, config->samples);

        printf("transfer,%s,0x%04x,%zu,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,ok\n",
            suite_spec->label, suite_spec->cipher_suite_id, config->transfer_bytes, config->transfer_iters,
            config->samples, mbps_stats.mean, mbps_stats.median, mbps_stats.min, mbps_stats.max,
            usec_stats.mean, usec_stats.median, usec_stats.min, usec_stats.max);
        fflush(stdout);
    }

    return ret;
}

int main(int argc, char** argv)
{
    aegis_perf_config_t config = { 5, 10000, 16384, 1, 2 * 1024 * 1024 };
    int ret = aegis_perf_parse_args(argc, argv, &config);

    if (ret != 0) {
        aegis_perf_usage(argv[0]);
        return 1;
    }

    debug_printf_suspend();
    picoquic_set_solution_dir(".");
    picoquic_tls_api_init();

    printf("# samples=%zu micro_iters=%zu micro_bytes=%zu transfer_iters=%zu transfer_bytes=%zu\n",
        config.samples, config.micro_iters, config.micro_bytes, config.transfer_iters, config.transfer_bytes);
    printf("scope,suite,id,bytes,iters,samples,mean_mbps,median_mbps,min_mbps,max_mbps,mean_us,median_us,min_us,max_us,status\n");

    for (size_t i = 0; ret == 0 && i < sizeof(aegis_perf_suites) / sizeof(aegis_perf_suites[0]); i++) {
        ret = aegis_perf_micro_one(&aegis_perf_suites[i], &config);
    }

    for (size_t i = 0; ret == 0 && i < sizeof(aegis_perf_suites) / sizeof(aegis_perf_suites[0]); i++) {
        ret = aegis_perf_transfer_one(&aegis_perf_suites[i], &config);
    }

    picoquic_tls_api_unload();
    return ret == 0 ? 0 : 1;
}

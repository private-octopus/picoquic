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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include "bytestream.h"
#include "csv.h"
#include "svg.h"
#include "qlog.h"
#include "cidset.h"
#include "logreader.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic.h"
#include "picoquic_binlog.h"
#include "autoqlog.h"
#include "picoquic_qlog_fns.h"

/*
* Unit tests of autoqlog functions that are not covered in end to end tests.
*/
#define AUTOQLOG_BAD_QLOG "no_such_folder/bad\\folder"

int autoqlog_bad_file(void)
{
	picoquic_quic_t* quic = NULL;
	picoquic_cnx_t* cnx = NULL;

	int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);
	if (ret == 0) {
		picoquic_set_binlog(quic, ".");
		ret = picoquic_set_qlog(quic, AUTOQLOG_BAD_QLOG);
	}
	if (ret == 0) {
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int autoqlog_no_binlog(void)
{
	picoquic_quic_t* quic = NULL;
	picoquic_cnx_t* cnx = NULL;

	int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);
	if (ret == 0) {
		picoquic_set_binlog(quic, ".");
		ret = picoquic_set_qlog(quic, ".");
	}
	if (ret == 0) {
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
#if 0
		picoquic_string_free(cnx->binlog_file_name);
		cnx->binlog_file_name = picoquic_string_duplicate(AUTOQLOG_BAD_QLOG);
#endif
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int autoqlog_longdir(void)
{
	picoquic_quic_t* quic = NULL;
	picoquic_cnx_t* cnx = NULL;
	char long_qlog[512];

	memset(long_qlog, 'x', 511);
	long_qlog[511] = 0;

	int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);
	if (ret == 0) {
		picoquic_set_binlog(quic, ".");
		ret = picoquic_set_qlog(quic, long_qlog);
	}
	if (ret == 0) {
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int autoqlog_unique(void)
{
	picoquic_quic_t* quic = NULL;
	picoquic_cnx_t* cnx = NULL;
	char long_qlog[512];

	memset(long_qlog, 'x', 511);
	long_qlog[511] = 0;

	int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);
	if (ret == 0) {
		picoquic_use_unique_log_names(quic, 1);
		picoquic_set_binlog(quic, ".");
		ret = picoquic_set_qlog(quic, long_qlog);
	}
	if (ret == 0) {
		/* TODO: fix that, It assumes that binlog is the only method declared in context. */
		binlog_new_connection(cnx, (void*)".", & cnx->log_ctx[0]);
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int qlog_auto_test(void)
{
	int ret = autoqlog_bad_file();

	if (ret == 0) {
		ret = autoqlog_no_binlog();
	}

	if (ret == 0) {
		ret = autoqlog_longdir();
	}

	if (ret == 0) {
		ret = autoqlog_unique();
	}

	return ret;
}


#define QLOG_ERROR_FILE "qlog_error_test.txt"

int qlog_chars(FILE* f, bytestream* s, uint64_t l);

int qlog_error_string(FILE* F)
{
	int ret = 0;
	bytestream bs = { 0 };
	uint8_t char_data[] = {
		'\"', '\\', 0xFF, ' ', 'z', 127
	};

	bs.data = char_data;
	bs.size = sizeof(char_data);
	bs.ptr = 0;
	if (qlog_chars(F, &bs, 2 * bs.size) == 0) {
		ret = -1;
	}

	if (ret == 0) {
		fprintf(F, "\n");
		bs.data = char_data;
		bs.size = sizeof(char_data);
		bs.ptr = 0;
		if (qlog_chars(F, &bs, bs.size) != 0) {
			ret = -1;
		}
	}
	return ret;
}

/* Test common function for writing a byte string with proper escape for JSON */
int qlog_fns_chars(FILE* f, const uint8_t* s, uint64_t l);
#define QLOG_JSON_ESCAPE_FILE "qlol_json_escape_file.txt"

int qlog_json_escape_test(void)
{
	int ret = 0;
	static const uint8_t escape_input[] = { 0xFF, 0x01, 0x7F };
	static const char* expected = "\"\\u00ff\\u0001\\u007f\"";
	char line[256];
	FILE* F;

	F = picoquic_file_open(QLOG_JSON_ESCAPE_FILE, "w");
	if (F == NULL) {
		ret = -1;
	}
	else {
		qlog_fns_chars(F, escape_input, sizeof(escape_input));
		F = picoquic_file_close(F);
	}

	if (ret == 0) {
		F = picoquic_file_open(QLOG_JSON_ESCAPE_FILE, "r");
		if (F == NULL || fgets(line, sizeof(line), F) == NULL || strcmp(line, expected) != 0) {
			DBG_PRINTF("qlog_fns_chars did not escape as %s", expected);
			ret = -1;
		}
		if (F != NULL) {
			F = picoquic_file_close(F);
		}
	}

	if (ret == 0) {
		bytestream bs = { 0 };
		bs.data = (uint8_t*)escape_input;
		bs.size = sizeof(escape_input);
		bs.ptr = 0;

		F = picoquic_file_open(QLOG_JSON_ESCAPE_FILE, "w");
		if (F == NULL) {
			ret = -1;
		}
		else {
			qlog_chars(F, &bs, bs.size);
			F = picoquic_file_close(F);
		}
	}

	if (ret == 0) {
		F = picoquic_file_open(QLOG_JSON_ESCAPE_FILE, "r");
		if (F == NULL || fgets(line, sizeof(line), F) == NULL || strcmp(line, expected) != 0) {
			DBG_PRINTF("qlog_chars did not escape as %s", expected);
			ret = -1;
		}
		if (F != NULL) {
			F = picoquic_file_close(F);
		}
	}

	return ret;
}

static uint8_t qlog_pref_addr[] = {
	/* IPv4 address */
	10, 0, 0, 1,
	/* IPv4 port */
	1, 4,
	/* IPv6 address */
	2, 1, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	/* IPv6 port */
	2, 8,
	/* CID len */
	4,
	/* CID value */
	15, 14, 13, 12,
	/* Reset token */
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	/* 4 extra bytes */
	16, 17, 18, 19
};

/* test proper rendering of preferred IPv4 address in qlog. */
#define QLOG_FNS_PREFADDR_FILE "qlog_fns_preferred_address_test.txt"
static uint8_t qlog_fns_pref_addr_bytes[] = {
    /* IPv4 address */
    10, 0, 0, 99,
    /* IPv4 port */
    1, 4,
    /* IPv6 address */
    2, 1, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
    /* IPv6 port */
    2, 8,
    /* CID len */
    4,
    /* CID value */
    15, 14, 13, 12,
    /* Reset token */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};
void qlog_fns_preferred_address(FILE* f, const uint8_t* bytes, uint64_t len);

/* Render bytes/len through qlog_fns_preferred_address and compare the whole file
 * content against expected, potentially detecting JSON formatting errors. */
static int qlog_fns_pref_addr_check(const uint8_t* bytes, uint64_t len, char const* expected)
{
    int ret = 0;
    char line[512];
    FILE* F = picoquic_file_open(QLOG_FNS_PREFADDR_FILE, "w");

    if (F == NULL) {
        ret = -1;
    }
    else {
        qlog_fns_preferred_address(F, bytes, len);
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        F = picoquic_file_open(QLOG_FNS_PREFADDR_FILE, "r");
        if (F == NULL) {
            ret = -1;
        }
        else {
            char* line_read = fgets(line, sizeof(line), F);
            if (line_read == NULL || strcmp(line_read, expected) != 0) {
                DBG_PRINTF("Unexpected preferred address rendering: %s", (line_read == NULL) ? "(empty)" : line_read);
                ret = -1;
            }
            F = picoquic_file_close(F);
        }
    }

    return ret;
}

int qlog_fns_pref_addr_test(void)
{
    int ret = 0;
    /* Exactly the four bytes the "len >= 4" admission check guarantees -- reading past it is the OOB bug this guards against. The trailing "port_v4":0 is a separate pre-existing quirk: that field prints before its own failed decode is checked. */
    uint8_t* min_bytes = (uint8_t*)malloc(4);

    if (min_bytes == NULL) {
        ret = -1;
    }
    else {
        memcpy(min_bytes, qlog_fns_pref_addr_bytes, 4);
        ret = qlog_fns_pref_addr_check(min_bytes, 4, "{\"ip_v4\": \"10.0.0.99\", \"port_v4\":0}");
        free(min_bytes);
    }

    /* The address ends after the IPv4 port: the IPv6 string must still be closed. */
    if (ret == 0) {
        ret = qlog_fns_pref_addr_check(qlog_fns_pref_addr_bytes, 6,
            "{\"ip_v4\": \"10.0.0.99\", \"port_v4\":260, \"ip_v6\": \"0\"}");
    }

    /* Full TP, no extra bytes. */
    if (ret == 0) {
        ret = qlog_fns_pref_addr_check(qlog_fns_pref_addr_bytes, sizeof(qlog_fns_pref_addr_bytes),
            "{\"ip_v4\": \"10.0.0.99\", \"port_v4\":260, \"ip_v6\": \"201:304:506:708:90a:b0c:d0e:f10\", "
            "\"port_v6\" : 520, \"connection_id\": \"0f0e0d0c\", "
            "\"stateless_reset_token\": \"000102030405060708090a0b0c0d0e0f\"}");
    }

    /* Full TP, with 4 trailing extra bytes -- exercises the "extra_bytes" field and the separator before it. */
    if (ret == 0) {
        ret = qlog_fns_pref_addr_check(qlog_pref_addr, sizeof(qlog_pref_addr),
            "{\"ip_v4\": \"10.0.0.1\", \"port_v4\":260, \"ip_v6\": \"201:304:506:708:90a:b0c:d0e:f10\", "
            "\"port_v6\" : 520, \"connection_id\": \"0f0e0d0c\", "
            "\"stateless_reset_token\": \"000102030405060708090a0b0c0d0e0f\", \"extra_bytes\": \"10111213\"}");
    }

    return ret;
}

static uint8_t qlog_vnego_tp_input[] = {
	0, 0, 0, 2,
	0, 0, 0, 1,
	1, 2, 3, 4,
	5, 6, 7, 8
};

#define QLOG_FNS_VNEGO_FILE "qlog_fns_tp_version_negotiation_test.txt"
void qlog_fns_tp_version_negotiation(FILE* f, const uint8_t* bytes, uint64_t len);

static int qlog_fns_vnego_check(const uint8_t* bytes, uint64_t len, char const* expected)
{
    int ret = 0;
    char line[512];
    FILE* F = picoquic_file_open(QLOG_FNS_VNEGO_FILE, "w");

    if (F == NULL) {
        ret = -1;
    }
    else {
        qlog_fns_tp_version_negotiation(F, bytes, len);
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        ret = picoquic_check_json_well_formed(QLOG_FNS_VNEGO_FILE);
        if (ret != 0) {
            DBG_PRINTF("%s", "Version negotiation TP rendering is not well-formed JSON.");
        }
    }

    if (ret == 0) {
        F = picoquic_file_open(QLOG_FNS_VNEGO_FILE, "r");
        if (F == NULL) {
            ret = -1;
        }
        else {
            char* line_read = fgets(line, sizeof(line), F);
            if (line_read == NULL || strcmp(line_read, expected) != 0) {
                DBG_PRINTF("Unexpected version negotiation TP rendering: %s", (line_read == NULL) ? "(empty)" : line_read);
                ret = -1;
            }
            F = picoquic_file_close(F);
        }
    }

    return ret;
}

/* Render version-negotiation TP bytes through qlog_fns_tp_version_negotiation,
 * checking both exact content and that
 * the output is well-formed JSON -- qlog_fns_tp_version_negotiation used to omit its
 * opening "{", and its "bad_length" branch used to leave a string unterminated. */
int qlog_fns_vnego_test(void)
{
    int ret = qlog_fns_vnego_check(qlog_vnego_tp_input, sizeof(qlog_vnego_tp_input),
        "{\"chosen\": \"00000002\", \"others\": [\"00000001\",\"01020304\",\"05060708\"]}");

    if (ret == 0) {
        /* One version only: no "others" list. */
        ret = qlog_fns_vnego_check(qlog_vnego_tp_input, 4, "{\"chosen\": \"00000002\"}");
    }

    if (ret == 0) {
        /* Two versions: one entry in "others". */
        ret = qlog_fns_vnego_check(qlog_vnego_tp_input, 8, "{\"chosen\": \"00000002\", \"others\": [\"00000001\"]}");
    }

    if (ret == 0) {
        /* Length not a multiple of 4: exercises the "bad_length" branch. */
        ret = qlog_fns_vnego_check(qlog_vnego_tp_input, 15, "{\"bad_length\": \"15\"}");
    }

    if (ret == 0) {
        /* Zero length is also treated as "bad_length". */
        ret = qlog_fns_vnego_check(qlog_vnego_tp_input, 0, "{\"bad_length\": \"0\"}");
    }

    return ret;
}

#define QLOG_FNS_TP_FILE "qlog_fns_transport_extensions_test.txt"
void qlog_fns_transport_extensions(FILE* f, uint8_t* tp, size_t tp_length);

/* picoquic encodes enable_time_stamp as a varint, and reset_stream_at as a
 * flag with no value. Check that qlog writes a number and an empty string. */
int qlog_fns_tp_types_test(void)
{
    static uint8_t tp[] = {
        0x80, 0x00, 0x71, 0x58, 1, 3, /* enable_time_stamp = 3 */
        picoquic_tp_reset_stream_at, 0
    };
    static char const* expected = ",\n    \"enable_time_stamp\" : 3,\n    \"reset_stream_at\" : \"\"";
    int ret = 0;
    char text[256];
    size_t text_length = 0;
    FILE* F = picoquic_file_open(QLOG_FNS_TP_FILE, "wb");

    if (F == NULL) {
        ret = -1;
    }
    else {
        qlog_fns_transport_extensions(F, tp, sizeof(tp));
        F = picoquic_file_close(F);
        if ((F = picoquic_file_open(QLOG_FNS_TP_FILE, "rb")) == NULL) {
            ret = -1;
        }
        else {
            text_length = fread(text, 1, sizeof(text) - 1, F);
            F = picoquic_file_close(F);
            text[text_length] = 0;
            if (strcmp(text, expected) != 0) {
                DBG_PRINTF("Unexpected transport parameter rendering: <%s>", text);
                ret = -1;
            }
        }
    }

    return ret;
}

uint8_t qlog_tp_extension_input[] = {
	picoquic_tp_ack_delay_exponent, 1, 3,
	picoquic_tp_server_preferred_address, 45,
	/* IPv4 address */
	10, 0, 0, 1,
	/* IPv4 port */
	1, 4,
	/* IPv6 address */
	2, 1, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	/* IPv6 port */
	2, 8,
	/* CID len */
	4,
	/* CID value */
	15, 14, 13, 12,
	/* Reset token */
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	picoquic_tp_disable_migration, 0,
	picoquic_tp_retry_connection_id, 5, 10, 11, 12, 13, 14,
	0x40 + (uint8_t)(picoquic_tp_grease_quic_bit >> 8),
	(uint8_t)(picoquic_tp_grease_quic_bit & 0xff), 0,
	picoquic_tp_version_negotiation, 8,
	0, 0, 0, 2, 0, 0, 0, 1,
	0x80, 0, (uint8_t)(picoquic_tp_enable_bdp_frame >> 8),
	(uint8_t)(picoquic_tp_enable_bdp_frame & 0xff), 1, 1,
	0xc0, 0, 0, 0xab, 0xba, 0xca, 0xda, 0xba, 5,
	0xab, 0xba, 0xca, 0xda, 0xba
};

int qlog_transport_extensions(FILE* f, bytestream* s, size_t tp_length);
int qlog_tp_extension_test(FILE* F)
{
	int ret = 0;
	bytestream bs = { 0 };
	size_t size_before = ftell(F);
	size_t size_after = 0;
	size_t test_len[5] = {
		sizeof(qlog_tp_extension_input),
		2 * sizeof(qlog_tp_extension_input),
		1,
		2,
		sizeof(qlog_tp_extension_input) - 1
	};

	for (int i = 0; i < 5; i++) {
		fprintf(F, "\n");
		bs.data = qlog_tp_extension_input;
		bs.size = sizeof(qlog_tp_extension_input);
		bs.ptr = 0;
		qlog_transport_extensions(F, &bs, test_len[i]);
	}

	size_after = ftell(F);
	if (size_after < size_before + 32) {
		ret = -1;
	}
	return ret;
}

#define QLOG_FNS_FORMAT_FILE "qlog_fns_format_test.txt"
#define QLOG_FNS_FORMAT_REF "qlog_fns_format_ref.txt"
const uint8_t* qlog_frame_hex_string(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, uint64_t l);

/* qlog_fns_text_uint, qlog_fns_text_int and qlog_frame_hex_string format
 * numbers and hex bytes without fprintf. Write the same output with fprintf
 * to a second file, and compare the two files. Use numbers at the limits of
 * their type, and a hex string that is longer than the local buffer of
 * qlog_frame_hex_string. */
int qlog_fns_format_test(void)
{
    static const uint64_t values[] = {
        0, 1, 9, 10, 99, 100, 1234567890, (uint64_t)INT64_MAX, (uint64_t)INT64_MAX + 1, UINT64_MAX
    };
    static const int64_t signed_values[] = { -1, -9, -10, -1234567890, INT64_MIN + 1, INT64_MIN };
    /* The helper writes the text with fputs if the text and the digits need
     * more than 127 bytes. This keeps room for a sign in its 128-byte buffer.
     * For UINT64_MAX and INT64_MIN, the longest texts kept in the buffer have
     * 107 and 108 characters. Test the text lengths around these limits. */
    char long_text[111];
    uint8_t hex_bytes[300];
    int ret = 0;
    FILE* F = picoquic_file_open(QLOG_FNS_FORMAT_FILE, "wb");
    FILE* F_ref = picoquic_file_open(QLOG_FNS_FORMAT_REF, "wb");

    if (F == NULL || F_ref == NULL) {
        ret = -1;
    }
    else {
        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
            qlog_fns_text_uint(F, ", u=", values[i]);
            qlog_fns_text_int(F, ", i=", (int64_t)values[i]);
            fprintf(F_ref, ", u=%" PRIu64 ", i=%" PRId64, values[i], (int64_t)values[i]);
        }
        for (size_t i = 0; i < sizeof(signed_values) / sizeof(signed_values[0]); i++) {
            qlog_fns_text_int(F, ", i=", signed_values[i]);
            fprintf(F_ref, ", i=%" PRId64, signed_values[i]);
        }
        for (size_t text_length = 106; text_length < sizeof(long_text); text_length++) {
            memset(long_text, 'x', text_length);
            long_text[text_length] = 0;
            qlog_fns_text_uint(F, long_text, UINT64_MAX);
            qlog_fns_text_int(F, long_text, INT64_MIN);
            fprintf(F_ref, "%s%" PRIu64 "%s%" PRId64, long_text, UINT64_MAX, long_text, INT64_MIN);
        }
        for (size_t i = 0; i < sizeof(hex_bytes); i++) {
            hex_bytes[i] = (uint8_t)(i * 7 + 3);
        }
        (void)qlog_frame_hex_string(F, hex_bytes, hex_bytes + sizeof(hex_bytes), sizeof(hex_bytes));
        fprintf(F_ref, "\"");
        for (size_t i = 0; i < sizeof(hex_bytes); i++) {
            fprintf(F_ref, "%02x", hex_bytes[i]);
        }
        fprintf(F_ref, "\"");
        if (ferror(F) || ferror(F_ref)) {
            ret = -1;
        }
    }
    F = picoquic_file_close(F);
    F_ref = picoquic_file_close(F_ref);

    if (ret == 0) {
        ret = picoquic_test_compare_binary_files(QLOG_FNS_FORMAT_FILE, QLOG_FNS_FORMAT_REF);
    }

    return ret;
}

#define QLOG_DAMAGED_BINLOG "qlog_damaged_record_test.log"
#define QLOG_DAMAGED_QLOG "qlog_damaged_record_test.qlog"

static int qlog_damaged_write_record(FILE* F, const picoquic_connection_id_t* cid, uint64_t event_id,
    const uint8_t* data, size_t length)
{
    bytestream_buf stream;
    bytestream* ps = bytestream_buf_init(&stream, BYTESTREAM_MAX_BUFFER_SIZE);
    uint8_t head[4];
    int ret = 0;

    ret |= bytewrite_cid(ps, cid);
    ret |= bytewrite_vint(ps, 10); /* time */
    ret |= bytewrite_vint(ps, 0); /* path id */
    ret |= bytewrite_vint(ps, event_id);
    if (length > 0) {
        ret |= bytewrite_buffer(ps, data, length);
    }

    if (ret == 0) {
        size_t record_length = bytestream_length(ps);
        head[0] = (uint8_t)(record_length >> 24);
        head[1] = (uint8_t)(record_length >> 16);
        head[2] = (uint8_t)(record_length >> 8);
        head[3] = (uint8_t)record_length;
        if (fwrite(head, sizeof(head), 1, F) <= 0 ||
            fwrite(bytestream_data(ps), record_length, 1, F) <= 0) {
            ret = -1;
        }
    }

    return ret;
}

/* Convert a binary log with damaged records. The qlog must not hold an
 * address, an ECN mark or a packet size that the record does not hold. */
int qlog_damaged_record_test(void)
{
    static const char* expected[] = {
        "[0, \"transport\", \"datagram_received\", { \"byte_length\": 0}]",
        "[0, \"transport\", \"datagram_received\", { \"byte_length\": 0, \"addr_from\" : {\"ip_v4\": \"10.0.0.1\", \"port_v4\":4433}}]",
        "        \"dcid\" : \"01020304\"}}]"
    };
    static const char* not_expected[] = { "ip_v6", "ecn", "packet_size" };
    picoquic_connection_id_t cid = { { 1, 2, 3, 4 }, 4 };
    struct sockaddr_in addr;
    bytestream_buf stream;
    bytestream* ps = bytestream_buf_init(&stream, BYTESTREAM_MAX_BUFFER_SIZE);
    char qlog_text[2048];
    size_t qlog_length = 0;
    uint16_t flags = 0;
    uint64_t log_time = 0;
    FILE* F = picoquic_file_open(QLOG_DAMAGED_BINLOG, "wb");
    int ret = (F == NULL) ? -1 : 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 4433;
    ((uint8_t*)&addr.sin_addr)[0] = 10;
    ((uint8_t*)&addr.sin_addr)[3] = 1;

    if (ret == 0) {
        /* File header */
        ret |= bytewrite_int32(ps, FOURCC('q', 'l', 'o', 'g'));
        ret |= bytewrite_int16(ps, 0);
        ret |= bytewrite_int16(ps, 1);
        ret |= bytewrite_int64(ps, 0);
        if (ret == 0 && fwrite(bytestream_data(ps), bytestream_length(ps), 1, F) <= 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* New connection */
        ps = bytestream_buf_init(&stream, BYTESTREAM_MAX_BUFFER_SIZE);
        ret |= bytewrite_int8(ps, 1);
        ret |= bytewrite_int32(ps, 1);
        ret |= bytewrite_cid(ps, &cid);
        if (ret == 0) {
            ret = qlog_damaged_write_record(F, &cid, picoquic_log_event_new_connection,
                bytestream_data(ps), bytestream_length(ps));
        }
    }
    if (ret == 0) {
        /* PDU record with no data */
        ret = qlog_damaged_write_record(F, &cid, picoquic_log_event_pdu_recv, NULL, 0);
    }
    if (ret == 0) {
        /* PDU record that ends after the peer address */
        ps = bytestream_buf_init(&stream, BYTESTREAM_MAX_BUFFER_SIZE);
        ret |= bytewrite_addr(ps, (struct sockaddr*)&addr);
        if (ret == 0) {
            ret = qlog_damaged_write_record(F, &cid, picoquic_log_event_pdu_recv,
                bytestream_data(ps), bytestream_length(ps));
        }
    }
    if (ret == 0) {
        /* Lost packet record that ends before the packet size */
        ps = bytestream_buf_init(&stream, BYTESTREAM_MAX_BUFFER_SIZE);
        ret |= bytewrite_vint(ps, picoquic_packet_1rtt_protected);
        ret |= bytewrite_vint(ps, 42);
        ret |= bytewrite_cstr(ps, "timer");
        ret |= bytewrite_cid(ps, &cid);
        if (ret == 0) {
            ret = qlog_damaged_write_record(F, &cid, picoquic_log_event_packet_lost,
                bytestream_data(ps), bytestream_length(ps));
        }
    }
    if (F != NULL) {
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        F = picoquic_open_cc_log_file_for_read(QLOG_DAMAGED_BINLOG, &flags, &log_time);
        if (F == NULL) {
            ret = -1;
        }
        else {
            ret = qlog_convert(&cid, F, QLOG_DAMAGED_BINLOG, QLOG_DAMAGED_QLOG, NULL, flags);
            if (ret != 0) {
                DBG_PRINTF("%s", "Damaged record test, cannot convert the binary log");
            }
            F = picoquic_file_close(F);
        }
    }

    if (ret == 0) {
        F = picoquic_file_open(QLOG_DAMAGED_QLOG, "r");
        if (F == NULL) {
            ret = -1;
        }
        else {
            qlog_length = fread(qlog_text, 1, sizeof(qlog_text) - 1, F);
            qlog_text[qlog_length] = 0;
            F = picoquic_file_close(F);
        }
    }

    for (size_t i = 0; ret == 0 && i < sizeof(expected) / sizeof(expected[0]); i++) {
        if (strstr(qlog_text, expected[i]) == NULL) {
            DBG_PRINTF("Damaged record test, missing: %s", expected[i]);
            ret = -1;
        }
    }
    for (size_t i = 0; ret == 0 && i < sizeof(not_expected) / sizeof(not_expected[0]); i++) {
        if (strstr(qlog_text, not_expected[i]) != NULL) {
            DBG_PRINTF("Damaged record test, unexpected: %s", not_expected[i]);
            ret = -1;
        }
    }

    return ret;
}

#define QLOG_PACKET_CONTENT_FILE "qlog_fns_packet_content_test.txt"
void qlog_fns_packet(picoquic_cnx_t* cnx, void* log_ctx, picoquic_path_t* path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t byte_length);
static int qlog_quic_fallback_check_file(char const* fname, char const** expected, size_t nb_expected);

/* The qlog must hold the proposed versions and the retry token of received packets. */
int qlog_fns_packet_content_test(void)
{
    static const char* expected[] = {
        "\"proposed_versions\": [\"00000001\", \"ff00001d\"]}]",
        "\"proposed_versions\": [\"00000001\", \"ff00001d\", \"... coding error!\"]}]",
        "\"retry_token\": \"a1a2a3a4a5a6a7a8\"}]",
        "\"packet_size\": 16 }}]"
    };
    static const uint8_t content[] = { 0, 0, 0, 1, 0xff, 0, 0, 0x1d, 0xa1 };
    /* A token of 8 bytes and an integrity tag of 16 bytes. */
    static const uint8_t retry_content[] = {
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
    };
    qlog_fns_context_t ctx = { 0 };
    picoquic_packet_header ph = { 0 };
    int ret = 0;

    ctx.f_txtlog = picoquic_file_open(QLOG_PACKET_CONTENT_FILE, "w");
    if (ctx.f_txtlog == NULL) {
        ret = -1;
    }
    else {
        ph.ptype = picoquic_packet_version_negotiation;
        qlog_fns_packet(NULL, &ctx, NULL, 1, 0, &ph, content, 8);
        /* The last version has only 1 byte. */
        qlog_fns_packet(NULL, &ctx, NULL, 1, 0, &ph, content, 9);
        ph.ptype = picoquic_packet_retry;
        qlog_fns_packet(NULL, &ctx, NULL, 1, 0, &ph, retry_content, sizeof(retry_content));
        /* The packet has only the integrity tag. */
        qlog_fns_packet(NULL, &ctx, NULL, 1, 0, &ph, retry_content + 8, 16);
        ctx.f_txtlog = picoquic_file_close(ctx.f_txtlog);
        ret = qlog_quic_fallback_check_file(QLOG_PACKET_CONTENT_FILE, expected, sizeof(expected) / sizeof(expected[0]));
    }

    return ret;
}

int qlog_error_test(void)
{
	FILE* F = picoquic_file_open(QLOG_ERROR_FILE, "w");
	int ret = (F == NULL) ? -1 : 0;

	if (ret == 0) {
		fprintf(F, "\n");
		ret = qlog_error_string(F);
		fprintf(F, "\n");
	}

	if (ret == 0) {
		ret = qlog_tp_extension_test(F);
		fprintf(F, "\n");
	}

	if (F != NULL) {
		F = picoquic_file_close(F);
	}

	if (ret == 0) {
		ret = qlog_fns_pref_addr_test();
	}

	if (ret == 0) {
		ret = qlog_fns_vnego_test();
	}

	if (ret == 0) {
		ret = qlog_fns_tp_types_test();
	}

	if (ret == 0) {
		ret = qlog_json_escape_test();
	}

	if (ret == 0) {
		ret = qlog_fns_format_test();
	}

	if (ret == 0) {
		ret = qlog_damaged_record_test();
	}

	if (ret == 0) {
		ret = qlog_fns_packet_content_test();
	}

	return ret;
}

/* Minimal structural well-formedness check: balanced {}/[] and properly closed,
 * properly escaped strings. Not a full RFC 8259 validator, but enough to catch the
 * class of bug where a frame-rendering off-by-one corrupts the JSON structure --
 * a text diff against a reference file would not catch that if the reference file was
 * itself generated from already-broken output. */
int picoquic_check_json_well_formed(char const* fname)
{
    int ret = 0;
    FILE* F = picoquic_file_open(fname, "r");

    if (F == NULL) {
        ret = -1;
    }
    else {
        int c;
        int in_string = 0;
        int is_escaped = 0;
        size_t depth = 0;
        char stack[256];
        long line = 1;

        while (ret == 0 && (c = fgetc(F)) != EOF) {
            if (c == '\n') {
                line++;
            }
            if (in_string) {
                if (is_escaped) {
                    is_escaped = 0;
                }
                else if (c == '\\') {
                    is_escaped = 1;
                }
                else if (c == '"') {
                    in_string = 0;
                }
                else if ((unsigned char)c < 0x20) {
                    DBG_PRINTF("Unescaped control character 0x%02x in JSON string, %s line %ld", c, fname, line);
                    ret = -1;
                }
            }
            else if (c == '"') {
                in_string = 1;
            }
            else if (c == '{' || c == '[') {
                if (depth >= sizeof(stack)) {
                    DBG_PRINTF("JSON nesting too deep in %s", fname);
                    ret = -1;
                }
                else {
                    stack[depth] = (char)c;
                    depth++;
                }
            }
            else if (c == '}' || c == ']') {
                char expected = (c == '}') ? '{' : '[';
                if (depth == 0 || stack[depth - 1] != expected) {
                    DBG_PRINTF("Unbalanced JSON closer '%c' in %s, line %ld", c, fname, line);
                    ret = -1;
                }
                else {
                    depth--;
                }
            }
        }

        if (ret == 0 && in_string) {
            DBG_PRINTF("JSON file %s ends inside an unterminated string", fname);
            ret = -1;
        }
        if (ret == 0 && depth != 0) {
            DBG_PRINTF("JSON file %s ends with %zu unclosed brace(s)/bracket(s)", fname, depth);
            ret = -1;
        }

        (void)picoquic_file_close(F);
    }

    return ret;
}

/* qlog_fns_new_connection names the output file after the initial CID's hex form
 * (see qlog_fns_set_file_name), so an explicit, non-random CID is needed here -- a
 * client-mode cnx created with a null initial CID gets a random one instead. */
#define QLOG_FNS_TRIM_FILE "09090909.client.qlog"

/* qlog_fns_get_path_context keeps a per-connection list of path contexts, one per
 * unique_path_id it has ever seen a cc_dump event for. When that list grows past the
 * connection's current number of paths, it calls qlog_fns_trim_path_contexts to drop
 * entries for paths that no longer exist. Exercise that by creating three paths, cc-
 * dumping all of them (three contexts remembered), abandoning one, then creating a new
 * path and cc-dumping again -- the new, not-yet-seen path id pushes the remembered count
 * over the live path count, triggering the trim of the abandoned path's stale entry. */
int qlog_fns_trim_path_contexts_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    const picoquic_connection_id_t initial_cid = {
        { 9, 9, 9, 9 }, 4
    };

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else if ((cnx = picoquic_create_cnx(quic, initial_cid, picoquic_null_connection_id,
        (struct sockaddr*)&saddr, simulated_time, 0, "test-sni", "test-alpn", 1)) == NULL) {
        ret = -1;
    }
    else {
        /* picoquic_create_path returns the new path's array index (>= 0) on success,
         * or -1 on failure -- it is not a plain 0/nonzero status code. */
        cnx->is_multipath_enabled = 1;

        if (picoquic_create_path(cnx, simulated_time, NULL, (struct sockaddr*)&saddr, 0, 1) < 0 ||
            picoquic_create_path(cnx, simulated_time, NULL, (struct sockaddr*)&saddr, 0, 2) < 0) {
            ret = -1;
        }
        else if (picoquic_set_qlog(quic, ".") != 0) {
            ret = -1;
        }
        else {
            picoquic_log_new_connection(cnx);

            /* Dump all three paths: creates three remembered path contexts. */
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->path[i]->is_cc_data_updated = 1;
            }
            picoquic_log_cc_dump(cnx, simulated_time);

            /* Abandon the path with unique_path_id 1. */
            picoquic_delete_path(cnx, 1);

            /* Create a new, not-yet-seen path: nb_paths is 3 again (ids 0, 2, 3), but
             * the qlog context list still has 3 entries for ids 0, 1, 2 -- adding a
             * context for id 3 pushes that list to 4, past nb_paths, triggering trim. */
            if (picoquic_create_path(cnx, simulated_time, NULL, (struct sockaddr*)&saddr, 0, 3) < 0) {
                ret = -1;
            }
            else {
                for (int i = 0; i < cnx->nb_paths; i++) {
                    cnx->path[i]->is_cc_data_updated = 1;
                }
                picoquic_log_cc_dump(cnx, simulated_time);
            }
        }

        picoquic_log_close_connection(cnx);
        picoquic_delete_cnx(cnx);
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    if (ret == 0) {
        ret = picoquic_check_json_well_formed(QLOG_FNS_TRIM_FILE);
        if (ret != 0) {
            DBG_PRINTF("%s", "Trim-path-contexts QLOG output is not well-formed JSON.");
        }
    }

    return ret;
}

#define QLOG_QUIC_FALLBACK_FILE "0a0b0c0d.client.qlog"

static int qlog_quic_fallback_check_file(char const* fname, char const** expected, size_t nb_expected)
{
    int ret = 0;
    FILE* F = picoquic_file_open(fname, "rb");
    char* buffer = NULL;
    size_t nb_read = 0;

    if (F == NULL || (buffer = (char*)malloc(0x10000)) == NULL) {
        DBG_PRINTF("Cannot read %s", fname);
        ret = -1;
    }
    else {
        nb_read = fread(buffer, 1, 0x10000 - 1, F);
        buffer[nb_read] = 0;
        for (size_t i = 0; ret == 0 && i < nb_expected; i++) {
            if (strstr(buffer, expected[i]) == NULL) {
                DBG_PRINTF("Missing <%s> in %s", expected[i], fname);
                ret = -1;
            }
        }
    }
    if (buffer != NULL) {
        free(buffer);
    }
    (void)picoquic_file_close(F);
    return ret;
}

/* The qlog backend provides neither log_quic_pdu nor log_quic_app_message. Verify that
 * picoquic_log_quic_pdu and picoquic_log_context_free_app_message are written instead in
 * the qlog of the first connection, and are safely skipped if there is no connection or
 * if that connection has no qlog context. */
int qlog_quic_fallback_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    struct sockaddr_storage addr_peer;
    struct sockaddr_storage addr_local;
    const picoquic_connection_id_t initial_cid = { { 10, 11, 12, 13 }, 4 };
    char const* expected[] = {
        "\"datagram_received\"",
        "\"byte_length\": 1234",
        "\"message\": \"Stateless reset test 17\""
    };

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL ||
        picoquic_store_text_addr(&addr_peer, "10.0.0.1", 4433) != 0 ||
        picoquic_store_text_addr(&addr_local, "10.0.0.2", 1234) != 0 ||
        picoquic_set_qlog(quic, ".") != 0) {
        ret = -1;
    }
    else {
        /* No connection yet: nothing can be logged, but nothing should break. */
        picoquic_log_quic_pdu(quic, 1, simulated_time, 0, (struct sockaddr*)&addr_peer,
            (struct sockaddr*)&addr_local, 1000);
        picoquic_log_context_free_app_message(quic, &initial_cid, "No connection test %d", 1);

        if ((cnx = picoquic_create_cnx(quic, initial_cid, picoquic_null_connection_id,
            (struct sockaddr*)&addr_peer, simulated_time, 0, "test-sni", "test-alpn", 1)) == NULL) {
            ret = -1;
        }
        else {
            /* Client connection not started yet, thus without qlog context. */
            picoquic_log_quic_pdu(quic, 1, simulated_time, 0, (struct sockaddr*)&addr_peer,
                (struct sockaddr*)&addr_local, 1100);
            picoquic_log_context_free_app_message(quic, &initial_cid, "No context test %d", 2);

            picoquic_log_new_connection(cnx);
            if (cnx->log_ctx[0] == NULL) {
                DBG_PRINTF("%s", "Expected a qlog context after picoquic_log_new_connection.");
                ret = -1;
            }
            else {
                simulated_time += 1000;
                picoquic_log_quic_pdu(quic, 1, simulated_time, 0, (struct sockaddr*)&addr_peer,
                    (struct sockaddr*)&addr_local, 1234);
                picoquic_log_context_free_app_message(quic, &initial_cid, "Stateless reset test %d", 17);
            }
            picoquic_log_close_connection(cnx);
            picoquic_delete_cnx(cnx);
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    if (ret == 0 && (ret = picoquic_check_json_well_formed(QLOG_QUIC_FALLBACK_FILE)) != 0) {
        DBG_PRINTF("%s", "Quic fallback QLOG output is not well-formed JSON.");
    }

    if (ret == 0) {
        ret = qlog_quic_fallback_check_file(QLOG_QUIC_FALLBACK_FILE, expected, sizeof(expected) / sizeof(char const*));
    }

    return ret;
}


/* qlog_fns_new_connection checks current_number_of_open_logs against
 * max_simultaneous_logs. With the limit set to 1, only the first of two
 * simultaneous connections is logged, and a new connection can be logged
 * after the first one is closed. */
int qlog_max_simultaneous_logs_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx[3] = { NULL, NULL, NULL };
    char const* qlog_name[3] = { "0a0a0a0a.client.qlog", "0b0b0b0b.client.qlog", "0c0c0c0c.client.qlog" };
    int expect_qlog[3] = { 1, 0, 1 };
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;

    for (int i = 0; i < 3; i++) {
        (void)picoquic_file_delete(qlog_name[i], NULL);
    }

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL || picoquic_set_qlog(quic, ".") != 0) {
        ret = -1;
    }
    else {
        picoquic_set_max_simultaneous_logs(quic, 1);

        for (int i = 0; ret == 0 && i < 3; i++) {
            uint8_t id = (uint8_t)(0x0a + i);
            picoquic_connection_id_t initial_cid = { { id, id, id, id }, 4 };

            if (i == 2) {
                /* Closing the first connection frees its log slot. */
                picoquic_delete_cnx(cnx[0]);
                cnx[0] = NULL;
            }
            if ((cnx[i] = picoquic_create_cnx(quic, initial_cid, picoquic_null_connection_id,
                (struct sockaddr*)&saddr, simulated_time, 0, "test-sni", "test-alpn", 1)) == NULL ||
                picoquic_start_client_cnx(cnx[i]) != 0) {
                ret = -1;
            }
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    for (int i = 0; i < 3; i++) {
        FILE* F = picoquic_file_open(qlog_name[i], "r");
        int is_present = (F != NULL);

        if (F != NULL) {
            (void)picoquic_file_close(F);
            (void)picoquic_file_delete(qlog_name[i], NULL);
        }
        if (ret == 0 && is_present != expect_qlog[i]) {
            DBG_PRINTF("QLOG file %s is %s", qlog_name[i], (is_present) ? "present" : "missing");
            ret = -1;
        }
    }

    return ret;
}
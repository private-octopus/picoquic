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

/*
* Unit tests of autoqlog functions that are not covered in end to end tests.
*/
#define AUTOQLOG_BAD_QLOG "no_such_folder/bad\\folder"

int autoqlog_bad_file()
{
	picoquic_quic_t* quic = NULL;
	picoquic_cnx_t* cnx = NULL;

	int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);
	if (ret == 0) {
		picoquic_set_binlog(quic, ".");
		ret = picoquic_set_qlog(quic, AUTOQLOG_BAD_QLOG);
	}
	if (ret == 0) {
		binlog_new_connection(cnx);
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int autoqlog_no_binlog()
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

		picoquic_string_free(cnx->binlog_file_name);
		cnx->binlog_file_name = picoquic_string_duplicate(AUTOQLOG_BAD_QLOG);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int autoqlog_longdir()
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
		binlog_new_connection(cnx);
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int autoqlog_unique()
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
		binlog_new_connection(cnx);
		/* Initialize the client connection */
		ret = picoquic_start_client_cnx(cnx);
	}

	picoquic_test_delete_minimal_cnx(&quic, &cnx);
	return ret;
}

int qlog_auto_test()
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

int qlog_string(FILE* f, bytestream* s, uint64_t l);
int qlog_chars(FILE* f, bytestream* s, uint64_t l);

int qlog_error_string(FILE* F)
{
	int ret = 0;
	bytestream bs = { 0 };
	uint8_t char_data[] = {
		'\"', '\\', 0xFF, ' ', 'z', 127
	};
	uint8_t data[16];
	bs.data = data;
	bs.size = sizeof(data) - 1;
	bs.ptr = 0;
	memset(bs.data, 'x', sizeof(data) - 1);
	bs.data[sizeof(data) - 1] = 0;

	if (qlog_string(F, &bs, 2 * sizeof(data)) == 0) {
		ret = -1;
	}

	if (ret == 0) {
		fprintf(F, "\n");
		bs.data = char_data;
		bs.size = sizeof(char_data);
		bs.ptr = 0;
		if (qlog_chars(F, &bs, 2 * bs.size) == 0) {
			ret = -1;
		}
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
void qlog_preferred_address(FILE* f, bytestream* s, uint64_t len);

int qlog_pref_addr_test(FILE* F)
{
	int ret = 0;
	bytestream bs = { 0 };
	size_t size_before = ftell(F);
	size_t size_after = 0;
	
	bs.data = qlog_pref_addr;
	bs.size = sizeof(qlog_pref_addr);

	fprintf(F, "\n");
	qlog_preferred_address(F, &bs, sizeof(qlog_pref_addr));

	size_after = ftell(F);
	if (size_after < size_before + 32) {
		ret = -1;
	}
	return ret;
}

static uint8_t qlog_vnego_tp_input[] = {
	0, 0, 0, 2,
	0, 0, 0, 1,
	1, 2, 3, 4,
	5, 6, 7, 8
};

void qlog_tp_version_negotiation(FILE* f, bytestream* s, uint64_t len);
int qlog_pref_vnego_test(FILE* F)
{
	int ret = 0;
	bytestream bs = { 0 };
	size_t size_before = ftell(F);
	size_t size_after = 0;
	size_t test_len[7] = {
		4, 8, 12, 16, 20, 0, 15
	};

	for (int i = 0; i < 7; i++) {
		fprintf(F, "\n");
		bs.data = qlog_vnego_tp_input;
		bs.size = sizeof(qlog_vnego_tp_input);
		bs.ptr = 0;
		qlog_tp_version_negotiation(F, &bs, test_len[i]);
	}

	size_after = ftell(F);
	if (size_after < size_before + 32) {
		ret = -1;
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

int qlog_error_test()
{
	FILE* F = picoquic_file_open(QLOG_ERROR_FILE, "w");
	int ret = (F == NULL) ? -1 : 0;

	if (ret == 0) {
		fprintf(F, "\n");
		ret = qlog_error_string(F);
		fprintf(F, "\n");
	}

	if (ret == 0) {
		ret = qlog_pref_addr_test(F);
		fprintf(F, "\n");
	}

	if (ret == 0) {
		ret = qlog_pref_vnego_test(F);
		fprintf(F, "\n");
	}

	if (ret == 0) {
		ret = qlog_tp_extension_test(F);
		fprintf(F, "\n");
	}

	if (F != NULL) {
		F = picoquic_file_close(F);
	}
	return ret;
}

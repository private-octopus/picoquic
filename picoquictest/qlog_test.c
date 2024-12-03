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
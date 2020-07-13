/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/*
* Manage the qlog option, i.e. create a qlog upon completion of a binary log
*/

#include <stdarg.h>
#include "logreader.h"
#include "bytestream.h"
#include "qlog.h"
#include "picoquic_internal.h"
#include "picoquic.h"

int autoqlog(picoquic_cnx_t* cnx)
{
    int ret = 0;
    uint64_t log_time = cnx->start_time;
    FILE* f_binlog = picoquic_open_cc_log_file_for_read(cnx->binlog_file_name, &log_time);
    if (f_binlog == NULL) {
        DBG_PRINTF("Cannot open file %s for reading.\n", cnx->binlog_file_name);
        ret = -1;
    }
    else {
        char filename[512];
        char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];

        if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), &cnx->initial_cnxid) != 0) {
            DBG_PRINTF("Cannot convert connection id for %s", cnx->binlog_file_name);
            ret = -1;
        }
        else if (picoquic_sprintf(filename, sizeof(filename), NULL, "%s%s%s.%s.%s",
            cnx->quic->qlog_dir, PICOQUIC_FILE_SEPARATOR, cid_name,
            (cnx->client_mode) ? "client" : "server", "qlog") != 0) {
            DBG_PRINTF("Cannot format file name for connection %s in file %s", cid_name, cnx->binlog_file_name);
            ret = -1;
        }
        else {
            ret = qlog_convert(&cnx->initial_cnxid, f_binlog, cnx->binlog_file_name, filename, cnx->quic->qlog_dir);
            picoquic_file_close(f_binlog);
            if (ret != 0) {
                DBG_PRINTF("Cannot convert file %s to qlog, err = %d.\n", cnx->binlog_file_name, ret);
            }
            else {
                if (cnx->quic->binlog_dir == NULL) {
                    int last_err = 0;
                    if ((ret = picoquic_file_delete(cnx->binlog_file_name, &last_err)) != 0) {
                        DBG_PRINTF("Cannot delete file %s to qlog, err = %d.\n", cnx->binlog_file_name, last_err);
                    }
                }
            }
        }
    }

    return ret;
}

int picoquic_set_qlog(picoquic_quic_t* quic, char const* qlog_dir)
{
    quic->autoqlog_fn = autoqlog;
    quic->qlog_dir = picoquic_string_free(quic->qlog_dir);
    quic->qlog_dir = picoquic_string_duplicate(qlog_dir);
    return 0;
}
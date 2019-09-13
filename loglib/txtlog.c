/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
#include "picoquic_internal.h"
#include "bytestream.h"
#include "txtlog.h"

/* Open the bin file for reading */
FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint32_t * log_time)
{
    int ret = 0;
    FILE* f_binlog = picoquic_file_open(bin_cc_log_name, "rb");
    if (f_binlog == NULL) {
        DBG_PRINTF("Cannot open CC file %s.\n", bin_cc_log_name);
        ret = -1;
    }

    if (ret == 0) {
        bytestream_buf stream;
        bytestream* ps = bytestream_buf_init(&stream, 16);

        uint32_t fcc = 0;
        uint32_t version = 0;

        if (fread(stream.buf, bytestream_size(ps), 1, f_binlog) <= 0) {
            ret = -1;
            DBG_PRINTF("Cannot read header for file %s.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &fcc) != 0 || fcc != FOURCC('q', 'l', 'o', 'g')) {
            ret = -1;
            DBG_PRINTF("Header for file %s does not start with magic number.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &version) != 0 || version != 0x01) {
            ret = -1;
            DBG_PRINTF("Header for file %s requires unsupported version.\n", bin_cc_log_name);
        }
        else {
            ret = byteread_int32(ps, log_time);
        }
    }

    if (ret != 0) {
        f_binlog = picoquic_file_close(f_binlog);
    }

    return f_binlog;
}

/* Extract all picoquic_log_event_cc_update events from the binary log file and write them into an csv file. */
int picoquic_cc_bin_to_csv(FILE * f_binlog, FILE * f_csvlog)
{
    int ret = 0;

    /* TODO: maintain the list of headers as debugging data is added */
    ret |= fprintf(f_csvlog, "time, ") <= 0;
    ret |= fprintf(f_csvlog, "sequence, ") <= 0;
    ret |= fprintf(f_csvlog, "highest ack, ") <= 0;
    ret |= fprintf(f_csvlog, "high ack time, ") <= 0;
    ret |= fprintf(f_csvlog, "last time ack, ") <= 0;
    ret |= fprintf(f_csvlog, "cwin, ") <= 0;
    ret |= fprintf(f_csvlog, "SRTT, ") <= 0;
    ret |= fprintf(f_csvlog, "RTT min, ") <= 0;
    ret |= fprintf(f_csvlog, "Send MTU, ") <= 0;
    ret |= fprintf(f_csvlog, "pacing packet time(us), ") <= 0;
    ret |= fprintf(f_csvlog, "nb retrans, ") <= 0;
    ret |= fprintf(f_csvlog, "nb spurious, ") <= 0;
    ret |= fprintf(f_csvlog, "cwin blkd, ") <= 0;
    ret |= fprintf(f_csvlog, "flow blkd, ") <= 0;
    ret |= fprintf(f_csvlog, "stream blkd, ") <= 0;
    ret |= fprintf(f_csvlog, "\n") <= 0;

    bytestream_buf stream;
    bytestream* ps_head = bytestream_buf_init(&stream, 8);

    if (ps_head == NULL) {
        ret = -1;
    }

    while (ret == 0 && fread(stream.buf, bytestream_size(ps_head), 1, f_binlog) > 0) {

        uint32_t id, len;
        ret |= byteread_int32(ps_head, &id);
        ret |= byteread_int32(ps_head, &len);

        bytestream_reset(ps_head);

        if (ret == 0 && id == picoquic_log_event_cc_update) {

            bytestream_buf stream_msg;
            bytestream* ps_msg = bytestream_buf_init(&stream_msg, len);

            if (ps_msg == NULL || fread(stream_msg.buf, bytestream_size(ps_msg), 1, f_binlog) <= 0) {
                ret = -1;
            }
            else {
                uint64_t time = 0;
                uint64_t sequence = 0;
                uint64_t packet_rcvd = 0;
                uint64_t highest_ack = (uint64_t)(int64_t)-1;
                uint64_t high_ack_time = 0;
                uint64_t last_time_ack = 0;
                uint64_t cwin = 0;
                uint64_t SRTT = 0;
                uint64_t RTT_min = 0;
                uint64_t Send_MTU = 0;
                uint64_t pacing_packet_time = 0;
                uint64_t nb_retrans = 0;
                uint64_t nb_spurious = 0;
                uint64_t cwin_blkd = 0;
                uint64_t flow_blkd = 0;
                uint64_t stream_blkd = 0;

                ret |= byteread_vint(ps_msg, &time);
                ret |= byteread_vint(ps_msg, &sequence);
                ret |= byteread_vint(ps_msg, &packet_rcvd);
                if (packet_rcvd != 0) {
                    ret |= byteread_vint(ps_msg, &highest_ack);
                    ret |= byteread_vint(ps_msg, &high_ack_time);
                    ret |= byteread_vint(ps_msg, &last_time_ack);
                }
                ret |= byteread_vint(ps_msg, &cwin);
                ret |= byteread_vint(ps_msg, &SRTT);
                ret |= byteread_vint(ps_msg, &RTT_min);
                ret |= byteread_vint(ps_msg, &Send_MTU);
                ret |= byteread_vint(ps_msg, &pacing_packet_time);
                ret |= byteread_vint(ps_msg, &nb_retrans);
                ret |= byteread_vint(ps_msg, &nb_spurious);
                ret |= byteread_vint(ps_msg, &cwin_blkd);
                ret |= byteread_vint(ps_msg, &flow_blkd);
                ret |= byteread_vint(ps_msg, &stream_blkd);

                if (ret != 0 || fprintf(f_csvlog, "%" PRIu64 ", %" PRIu64 ", %" PRId64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", ",
                    time, sequence, (int64_t)highest_ack, high_ack_time, last_time_ack,
                    cwin, SRTT, RTT_min, Send_MTU, pacing_packet_time,
                    nb_retrans, nb_spurious, cwin_blkd, flow_blkd, stream_blkd) <= 0) {
                    ret = -1;
                    break;
                }
                if (ret == 0) {
                    if (fprintf(f_csvlog, "\n") <= 0) {
                        DBG_PRINTF("%s", "Error writing data\n");
                        ret = -1;
                    }
                }
            }
        }
        else {
            fseek(f_binlog, len, SEEK_CUR);
        }
    }

    return ret;
}

int picoquic_cc_log_file_to_csv(char const* bin_cc_log_name, char const* csv_cc_log_name)
{
    /* Open the bin file for reading, the csv file for writing */
    int ret = 0;
    uint32_t log_time = 0;
    FILE * f_binlog = picoquic_open_cc_log_file_for_read(bin_cc_log_name, &log_time);
    FILE * f_csvlog = picoquic_file_open(csv_cc_log_name, "w");

    if (f_binlog == NULL || f_csvlog == NULL) {
        ret = -1;
    } else {
        ret = picoquic_cc_bin_to_csv(f_binlog, f_csvlog);
    }
    (void)picoquic_file_close(f_csvlog);
    (void)picoquic_file_close(f_binlog);

    return ret;
}

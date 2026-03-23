/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WINDOWS
#include "wincompat.h"
#include "ws2ipdef.h"
#pragma warning(disable:4100)
#endif
#include "picoquic_internal.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "h09_server.h"
#include "democlient.h"
#include "demoserver.h"
#include "quicperf.h"

/* The HTTP 0.9 server code is used for early test of the QUIC transport functions. 
 * The simple server provides simple responses, precanned index files or randomly
 * generated content */

/* The code is designed to run either directly over QUIC, or over WT contexts */

char* strip_endofline(char* buf, size_t bufmax, char const* line)
{
    for (size_t i = 0; i < bufmax; i++) {
        int c = line[i];

        if (c == 0 || c == '\r' || c == '\n') {
            buf[i] = 0;
            break;
        }
        else {
            buf[i] = (char) c;
        }
    }

    buf[bufmax - 1] = 0;
    return buf;
}


static int picoquic_h09_server_parse_method(uint8_t* command, size_t command_length, size_t * consumed)
{
    int byte_index = 0;
    int ret = -1;

    if (command_length >= 3 && (command[0] == 'G' || command[0] == 'g') && (command[1] == 'E' || command[1] == 'e') && (command[2] == 'T' || command[2] == 't')) {
        ret = 0;
        byte_index = 3;
    } else if (command_length >= 4 && (command[0] == 'P' || command[0] == 'p') && (command[1] == 'O' || command[1] == 'o') && (command[2] == 'S' || command[2] == 's') && (command[3] == 'T' || command[3] == 't')) {
        ret = 1;
        byte_index = 4;
    }

    if (consumed) {
        *consumed = byte_index;
    }

    return ret;
}

static void picoquic_h09_server_parse_protocol(uint8_t* command, size_t command_length, int * proto, size_t * consumed)
{
    size_t byte_index = (command_length > 0)?command_length -1:0;
    size_t last_proto_index;
    int space_count = 0;

    *proto = 0;

    /* skip white space at the end */
    for (;;) {
        int c = command[byte_index];

        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            space_count++;
            if (byte_index > 0) {
                byte_index--;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }
    *consumed = space_count;
    last_proto_index = byte_index;

    /* find non space char */
    while (byte_index > 0) {
        int c = command[byte_index];

        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            byte_index++;
            break;
        }
        else {
            byte_index--;
        }
    }

    /* Parse protocol version */
    if (last_proto_index - byte_index == 7 &&
        command[byte_index + 6] == '.' &&
        command[byte_index + 4] == '/' &&
        (command[byte_index + 3] == 'p' || command[byte_index + 3] == 'P') &&
        (command[byte_index + 2] == 't' || command[byte_index + 2] == 'T') &&
        (command[byte_index + 1] == 't' || command[byte_index + 1] == 'T') &&
        (command[byte_index] == 'h' || command[byte_index] == 'H')) {
        int bad_version = 0;
        if (command[byte_index + 5] == '1' && (command[byte_index + 7] == '0' || command[byte_index + 7] == '1')) {
            *proto = 1;
        }
        else if (command[byte_index + 5] == '0' && command[byte_index + 7] == '9') {
            *proto = 0;
        }
        else {
            bad_version = 1;
        }

        if (!bad_version) {
            *consumed += 8;

            if (byte_index > 0) {
                byte_index--;
                while (byte_index > 0 && (command[byte_index] == ' ' || command[byte_index] == '\t')) {
                    byte_index--;
                    *consumed += 1;
                }
            }
        }
    }
}

/* TODO: the result of the parsing is in the "stream context", defined as 
* hq-> That should be promoted to an object independent of H3.
 */

int h09_server_parse_commandline(uint8_t* command, size_t command_length, h09_data_stream_state_t* hq)
{
    int ret = 0;
    size_t consumed;

    /* Find first line of command, ignore the rest */
    for (size_t i = 0; i < command_length; i++) {
        if (command[i] == '\r' || command[i] == '\n') {
            command_length = i;
            break;
        }
    }

    /* Parse protocol version and strip white spaces at the end of the command */
    picoquic_h09_server_parse_protocol(command, command_length, &hq->proto, &consumed);
    command_length -= consumed;

    /* parse the method */
    hq->method = picoquic_h09_server_parse_method(command, command_length, &consumed);

    /* Skip white spaces between method and path, and copy path if present */
    if (hq->method < 0) {
        ret = -1;
    }
    else {
        /* Skip at list one space */
        while (command_length > consumed && (command[consumed] == ' ' || command[consumed] == '\t')) {
            consumed++;
        }

        if (consumed >= command_length) {
            ret = -1;
        }
        else {
            size_t path_length = command_length - consumed;
            uint8_t* path = (uint8_t*)malloc(path_length + 1);

            if (path != NULL) {
                memcpy(path, command + consumed, path_length);
                path[path_length] = 0;
                hq->path = path;
                hq->path_length = path_length;
            }
            else {
                ret = -1;
            }
        }
    }

    return ret;
}

/*
 * Process the incoming data. 
 * We can expect the following:
 * - Initial command line: {GET|POST} <path> [HTTP/{0.9|1.0|1.1}] /r/n
 * - Additional command lines concluded with /r/n
 * - Empty line: /r/n
 * - Posted data
 * This can be interrupted at any time by a FIN mark. In the case of the 
 * GET command, there should not be any posted data. 
 * The server should parse the initial line to gather the type of command
 * and the name of the document. It should then parse data until the fin
 * mark is received.
 * The additional headers are ignored.
 * The amount of posted data is counted, will be used to prepare the response.
 *
 * The response is sent after the FIN is received (POST) or after the 
 * header line is fully parsed (GET).
 */

int h09_server_process_data_header(
    const uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event,
    h09_data_stream_state_t* hq,
    size_t * r_processed)
{
    int ret = 0;
    size_t processed = 0;

    while (ret == 0 && processed < length) {
        if (hq->status == picohttp_server_stream_status_none) {
            /* If the command has not been received yet, try to process it */
            int crlf_present = 0;

            while (processed < length && crlf_present == 0) {
                if (bytes[processed] == '\r') {
                    /* Ignore \r, so end of header is either CRLF/CRLF, of just LF/LF, or maybe LF/CR/LF */
                }
                else if (bytes[processed] == '\n') {
                    crlf_present = 1;
                }
                else if (hq->command_length < sizeof(hq->frame) - 1) {
                    hq->frame[hq->command_length++] = bytes[processed];
                }
                else {
                    /* Too much data */
                    hq->method = -1;
                    ret = -1;
                    break;
                }
                processed++;
            }

            if (crlf_present) {
                hq->status = picohttp_server_stream_status_crlf;
            }

            if (crlf_present || fin_or_event == picoquic_callback_stream_fin) {
                /* Parse the command */
                ret = h09_server_parse_commandline(hq->frame, hq->command_length, hq);
            }
        }
        else if (hq->status == picohttp_server_stream_status_crlf) {
            if (bytes[processed] == '\n') {
                /* empty line */
                hq->status = picohttp_server_stream_status_receiving;
            }
            else if (bytes[processed] != '\r') {
                hq->status = picohttp_server_stream_status_header;
            }
            processed++;
        }
        else if (hq->status == picohttp_server_stream_status_header) {
            if (bytes[processed] == '\n') {
                hq->status = picohttp_server_stream_status_crlf;
            }
            processed++;
        }
        else
        {
            break;
        }
    }

    *r_processed = processed;
    return ret;
}


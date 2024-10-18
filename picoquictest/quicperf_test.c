#include "picoquic_internal.h"
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picosplay.h"
#include "quicperf.h"

#define qpstr_batch "256:12345;"
#define qpstr_batch100 "* 100:256 : 12345;"
#define qpstr_batch2 "= b1:256 : 12345; = b2:=b1: 256 : 12345;"
#define qpstr_video1 "= v1:s30:n300:12345;"
#define qpstr_video2 "=v2:s30:p4:C:n300:12345;"
#define qpstr_video3 "=v3 : s30: p4:S: n1800:12345:G150:I11111;"
#define qpstr_video4 "=v4 : s30:p4:S:  n1800:12345:G150:I11111:D1000;"
#define qpstr_audio "=a0:d50:p2:C:n500:40;"
#define qpstr_combo "=a1:d50:p2:S:n3000:80; \
= vlow:*3 : s30 :p4:S:n1800 : 3750 : G150 : I37500; \
= vmid:*3 : s30 :p6:S: n1800 : 6250 : G150 : I62500 : D1000; \
= vhi:*3 : s30 :p8:S: n1800 : 12500 : G150 : I125000 : D1000;"

const quicperf_stream_desc_t qpsc_batch[1] = {
    {
    { 0, 0 }, /* id */
    { 0, 0 }, /* previous id */
    1, /* repeat_count */
    quicperf_media_batch, /* media_type */
    0, /* frequency */
    256, /* post_size */
    12345, /* response_size */
    0, /* nb_frames */
    0, /* frame_size */
    0, /* group_size */
    0, /* first_frame_size */
    0, /* reset_delay */
    0, /* priority */
    0, /* is_infinite */
    0, /*  is_client_media */
} };

const quicperf_stream_desc_t qpsc_batch100[1] = { {
    { 0, 0 }, /* id */
    { 0, 0 }, /* previous id */
    100, /* repeat_count */
    quicperf_media_batch, /* media_type */
    0, /* frequency */
    256, /* post_size */
    12345, /* response_size */
    0, /* nb_frames */
    0, /* frame_size */
    0, /* group_size */
    0, /* first_frame_size */
    0, /* reset_delay */
    0, /* priority */
    0, /* is_infinite */
    0, /*  is_client_media */
}};

const quicperf_stream_desc_t qpsc_batch2[2] = {
    {
        { 'b', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_batch, /* media_type */
        0, /* frequency */
        256, /* post_size */
        12345, /* response_size */
        0, /* nb_frames */
        0, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'b', '2', 0 }, /* id */
        { 'b', '1', 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_batch, /* media_type */
        0, /* frequency */
        256, /* post_size */
        12345, /* response_size */
        0, /* nb_frames */
        0, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video1[1] = {
    {
        { 'v', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        300, /* nb_frames */
        12345, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video2[1] = {
    {
        { 'v', '2', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        300, /* nb_frames */
        12345, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        1, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video3[] = {
    {
        { 'v', '3', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12345, /* frame_size */
        150, /* group_size */
        11111, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video4[] = {
    {
        { 'v', '4', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12345, /* frame_size */
        150, /* group_size */
        11111, /* first_frame_size */
        1000, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_audio[1] = {
    {
        { 'a', '0', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_datagram, /* media_type */
        50, /* frequency */
        0, /* post_size */
        0, /* response_size */
        500, /* nb_frames */
        40, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        2, /* priority */
        0, /* is_infinite */
        1, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_combo[4] = {
    {
        { 'a', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_datagram, /* media_type */
        50, /* frequency */
        0, /* post_size */
        0, /* response_size */
        3000, /* nb_frames */
        80, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        2, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'l', 'o', 'w',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        3750, /* frame_size */
        150, /* group_size */
        37500, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'm', 'i', 'd',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        6250, /* frame_size */
        150, /* group_size */
        62500, /* first_frame_size */
        1000, /* reset_delay */
        6, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'h', 'i',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12500, /* frame_size */
        150, /* group_size */
        125000, /* first_frame_size */
        1000, /* reset_delay */
        8, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

typedef struct st_quicperf_test_line_t {
    const quicperf_stream_desc_t* sc;
    size_t nb_sc;
    char const* str;
} quicperf_test_line_t;

const quicperf_test_line_t test_lines[] = {
    { qpsc_batch, 1, qpstr_batch },
    { qpsc_batch100, 1, qpstr_batch100 },
    { qpsc_batch2, 2, qpstr_batch2 },
    { qpsc_video1, 1, qpstr_video1 },
    { qpsc_video2, 1, qpstr_video2 },
    { qpsc_video3, 1, qpstr_video3 },
    { qpsc_video4, 1, qpstr_video4 },
    { qpsc_audio, 1, qpstr_audio },
    { qpsc_combo, 4, qpstr_combo }
};

const size_t nb_test_lines = sizeof(test_lines) / sizeof(quicperf_test_line_t);

int quicperf_compare_stream_desc(const quicperf_stream_desc_t* sc1, const quicperf_stream_desc_t* sc2)
{
    int ret = 0;
    char const* diff = NULL;

    if (strcmp(sc1->id, sc2->id) != 0) {
        diff = "id";
    }
    else if (strcmp(sc1->previous_id, sc2->previous_id) != 0) {
        diff = "previous_id";
    }
    else if (sc1->repeat_count != sc2->repeat_count) {
        diff = "repeat_count";
    }
    else if (sc1->media_type != sc2->media_type) {
        diff = "media_type";
    }
    else if (sc1->frequency != sc2->frequency) {
        diff = "frequency";
    }
    else if (sc1->post_size != sc2->post_size) {
        diff = "post_size";
    }
    else if (sc1->post_size != sc2->post_size) {
        diff = "post_size";
    }
    else if (sc1->response_size != sc2->response_size) {
        diff = "response_size";
    }
    else if (sc1->nb_frames != sc2->nb_frames) {
        diff = "nb_frames";
    }
    else if (sc1->frame_size != sc2->frame_size) {
        diff = "frame_size";
    }
    else if (sc1->group_size != sc2->group_size) {
        diff = "group_size";
    }
    else if (sc1->first_frame_size != sc2->first_frame_size) {
        diff = "first_frame_size";
    }
    else if (sc1->reset_delay != sc2->reset_delay) {
        diff = "reset_delay";
    }
    else if (sc1->priority != sc2->priority) {
        diff = "priority";
    }
    else if (sc1->is_infinite != sc2->is_infinite) {
        diff = "is_infinite";
    }
    else if (sc1->is_client_media != sc2->is_client_media) {
        diff = "is_client_media";
    }
    if (diff != NULL) {
        DBG_PRINTF("Values of %s do not match.\n", diff);
        ret = -1;
    }
    return ret;
}

int quicperf_parse_test_one(const quicperf_test_line_t* tl)
{
    int ret = 0;

    /* Parse the scenario */
    quicperf_ctx_t* ctx = quicperf_create_ctx(tl->str);
    if (ctx == NULL) {
        ret = -1;
    }
    else {
        /* Compare to the reference */
        if (ctx->nb_scenarios != tl->nb_sc) {
            DBG_PRINTF("Found %zu streams instead of %zu", ctx->nb_scenarios, tl->nb_sc);
            ret = -1;
        }
        else {
            for (size_t i = 0; ret == 0 && i < ctx->nb_scenarios; i++) {
                if (quicperf_compare_stream_desc(&ctx->scenarios[i], &tl->sc[i]) != 0) {
                    DBG_PRINTF("Stream descriptio %zu does not match", i);
                    ret = -1;
                }
            }
        }
        /* Free the scenario */
        quicperf_delete_ctx(ctx);
    }
    return ret;
}

int quicperf_parse_test()
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < nb_test_lines; i++) {
        ret = quicperf_parse_test_one(&test_lines[i]);
        if (ret != 0) {
            DBG_PRINTF("Parse test fails for test_lines[%zu]", i);
        }
    }
    return ret;
}
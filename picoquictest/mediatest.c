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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"

/* Media tests: simulate media transmission, include cases in which
* the media bandwidth is much lower than the available bandwidth on
* average, but sometimes higher when sending large frames. Also
* consider case of audio + video, sent as stream, together with
* data. Shall verify that audio and video delays do not suffer
* in presence of data streams.
* 
* This requires writing a data generation model that mimics real time.
* The network topology will be simple: client, server, link.
* 
* Data generation is linked to a callback. The callback accomodate for:
* - video generation model, 60 fps, combined one large "I" frame and
*   then 99 "P" frames, repeated three times.
* - Audio generation model, 50 fps, 30 bytes per frame.
* - Data generation model, some number of megabytes.
* 
* The test must verify that frame delays are within specified bounds.
* For that, we will format the frames:
* - length: in bytes
* - type: Audio, Video, Data.
* - time sent.
* 
*/

#define MEDIATEST_ALPN "picoquic_mediatest"
#define MEDIATEST_HEADER_SIZE 13
#define MEDIATEST_ERROR_INTERNAL 1

typedef enum {
    media_test_data = 0,
    media_test_audio,
    media_test_video
} media_test_type_enum;

typedef struct st_mediatest_message_buffer_t {
    size_t bytes_sent;
    size_t bytes_received;
    media_test_type_enum message_type;
    uint32_t message_size;
    uint64_t sent_time;
    uint8_t header[MEDIATEST_HEADER_SIZE];
} mediatest_message_buffer_t;

typedef struct st_mediatest_stream_ctx_t {
    /* Organize the streams as part of the connection */
    struct st_mediatest_stream_ctx_t* next_stream;
    struct st_mediatest_stream_ctx_t* previous_stream;
    struct st_mediatest_cnx_ctx_t* cnx_ctx;
    /* stream identifier */
    uint64_t stream_id;
    /* Specify the type of stream */
    media_test_type_enum stream_type;
    /* Specify the state of the stream: number of frames sent  or received */
    unsigned int is_sender : 1;
    uint64_t frames_sent;
    uint64_t frames_received;
    size_t bytes_sent;
    size_t bytes_received;
    uint64_t next_frame_time;

    mediatest_message_buffer_t message_sent;
    mediatest_message_buffer_t message_received;
} mediatest_stream_ctx_t;

/* Mediatest per connection context */
typedef struct st_mediatest_cnx_ctx_t {
    struct st_mediatest_cnx_ctx_t* next_cnx;
    struct st_mediatest_cnx_ctx_t* previous_cnx;
    struct st_mediatest_ctx_t* mt_ctx;

    char* sni;
    struct sockaddr_storage addr;
    picoquic_cnx_t* cnx;
    int is_server;

    struct st_mediatest_stream_ctx_t* first_stream;
    struct st_mediatest_stream_ctx_t* last_stream;
} mediatest_cnx_ctx_t;

/* Mediatest context */
typedef struct st_mediatest_ctx_t {
    uint64_t simulated_time;
    picoquic_quic_t* quic[2]; /* QUIC Context for client[0] or server[1] */
    picoquictest_sim_link_t* link[2]; /* Link from client to server [0] and back [1] */
    struct sockaddr_storage addr[2]; /* addresses of client [0] and server [1]*/
    mediatest_cnx_ctx_t* client_cnx; /* client connection context */
    struct st_mediatest_cnx_ctx_t* first_cnx;
    struct st_mediatest_cnx_ctx_t* last_cnx;
    /* Audio generation model */
    /* Video generation model */
    /* Data generation model */
    /* Statistics */
} mediatest_ctx_t;

int mediatest_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

static const uint8_t mediatest_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

mediatest_stream_ctx_t* mediatest_create_stream_context(mediatest_cnx_ctx_t* cnx_ctx, uint64_t stream_id)
{
    mediatest_stream_ctx_t* stream_ctx = (mediatest_stream_ctx_t*)malloc(sizeof(mediatest_stream_ctx_t));
    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(mediatest_stream_ctx_t));
        stream_ctx->cnx_ctx = cnx_ctx;
        stream_ctx->stream_id = stream_id;
        if (cnx_ctx->last_stream == NULL) {
            cnx_ctx->first_stream = stream_ctx;
        }
        else {
            cnx_ctx->last_stream->next_stream = stream_ctx;
        }
        stream_ctx->previous_stream = cnx_ctx->last_stream;
        cnx_ctx->last_stream = stream_ctx;
        /* simplification: only clients are senders. */
        stream_ctx->is_sender = !stream_ctx->cnx_ctx->is_server;
    }

    return stream_ctx;
}

mediatest_stream_ctx_t* mediatest_find_or_create_stream(
    uint64_t stream_id,
    mediatest_cnx_ctx_t* cnx_ctx,
    int should_create)
{
    mediatest_stream_ctx_t* stream_ctx = cnx_ctx->first_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->stream_id == stream_id) {
            break;
        }
        stream_ctx = stream_ctx->next_stream;
    }
    if (stream_ctx == NULL && should_create) {
        stream_ctx = mediatest_create_stream_context(cnx_ctx, stream_id);
    }

    return stream_ctx;
}

/* Delete a connection context */
void mediatest_delete_cnx_context(mediatest_cnx_ctx_t* cnx_ctx)
{
    /* TODO */
    return;
}

/* Create a connection context. 
* The QUIC connection has to be created before the QUICRQ connection. */
mediatest_cnx_ctx_t* mediatest_create_cnx_context(mediatest_ctx_t* mt_ctx, picoquic_cnx_t * cnx)
{
    mediatest_cnx_ctx_t* cnx_ctx = (mediatest_cnx_ctx_t*)malloc(sizeof(mediatest_cnx_ctx_t));

    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(mediatest_cnx_ctx_t));
        /* document quic connection */
        cnx_ctx->cnx = cnx;
        /* Add the connection in the double linked list */
        if (mt_ctx->last_cnx == NULL) {
            mt_ctx->first_cnx = cnx_ctx;
        }
        else {
            mt_ctx->last_cnx->next_cnx = cnx_ctx;
        }
        cnx_ctx->previous_cnx = mt_ctx->last_cnx;
        mt_ctx->last_cnx = cnx_ctx;
        cnx_ctx->mt_ctx = mt_ctx;
        picoquic_set_callback(cnx, mediatest_callback, cnx_ctx);
    }
    return cnx_ctx;
}

/* Receive stream data. This is composed of a set of messages.
 * All message received must have the same type
 * At the end of the message, compute and store delay statistics.
 * Messages are only received if not sender.
 * For sender, receiving FIN before sending it is an error.
 */
int mediatest_receive_stream_data(mediatest_stream_ctx_t* stream_ctx, uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;
    size_t msg_read = 0;
    size_t available = 0;
    if (length > msg_read && ret == 0) {
        if (stream_ctx->is_sender) {
            picoquic_log_app_message(stream_ctx->cnx_ctx->cnx, "MEDIATEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
            DBG_PRINTF("MEDIATEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
            ret = -1;
        }
        else {
            /* Receive the message buffer. If at least 2 bytes, compute the size. */
            while (length > msg_read && ret == 0 && stream_ctx->message_received.bytes_received < MEDIATEST_HEADER_SIZE) {
                stream_ctx->message_received.header[stream_ctx->message_received.bytes_received++] = bytes[msg_read++];
                if (stream_ctx->message_received.bytes_received == MEDIATEST_HEADER_SIZE) {
                    stream_ctx->message_received.message_type = stream_ctx->message_received.header[0];
                    if (picoquic_frames_uint32_decode(stream_ctx->message_received.header + 1,
                        stream_ctx->message_received.header + MEDIATEST_HEADER_SIZE, &stream_ctx->message_received.message_size) == NULL ||
                        picoquic_frames_uint64_decode(stream_ctx->message_received.header + 5,
                            stream_ctx->message_received.header + MEDIATEST_HEADER_SIZE, &stream_ctx->message_received.sent_time) == NULL) {
                        ret = -1;
                    }
                    else if (stream_ctx->frames_received > 0) {
                        if (stream_ctx->message_received.message_type != stream_ctx->stream_type) {
                            ret = -1;
                        }
                    }
                    else {
                        stream_ctx->stream_type = stream_ctx->message_received.message_type;
                    }
                }
            }
            if (length > msg_read && ret == 0) {
                available = length - msg_read;
                if (stream_ctx->message_received.bytes_received > stream_ctx->message_received.message_size) {
                    ret = -1;
                }
                else {
                    uint32_t required = stream_ctx->message_received.message_size - stream_ctx->message_received.bytes_received;
                    if (required <= available) {
                        /* Message is fully received */
                        stream_ctx->bytes_received += stream_ctx->message_received.bytes_received;
                        stream_ctx->frames_received += 1;
                        length -= required;
                        /* TODO: statistics on frame delay */
                        memset(&stream_ctx->message_received, 0, sizeof(mediatest_message_buffer_t));
                    }
                    else {
                        stream_ctx->bytes_received += available;
                        length = 0;
                    }
                }
            }
        }
    }
    return ret;
}

/* Send stream data.
 * For sender, if message is sent and time has come, create a new frame.
 * If frame data available, send it.
 * If no more frame, mark FIN.
 * For receiver, only send a FIN mark if FIN has been received.
 */
int mediatest_prepare_to_send_on_stream(mediatest_stream_ctx_t* stream_ctx, uint8_t* bytes, size_t length, uint64_t current_time)
{
    return -1;
}

/* Callback from Quic
*/
int mediatest_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{

    int ret = 0;
    mediatest_cnx_ctx_t* cnx_ctx = (mediatest_cnx_ctx_t*)callback_ctx;
    mediatest_stream_ctx_t* stream_ctx = (mediatest_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
    * to the default value defined for the server. This default value contains the pointer
    * to the global context in which streams and roles are defined.
    */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        if (fin_or_event == picoquic_callback_close) {
            picoquic_set_callback(cnx, NULL, NULL);
            return 0;
        }
        else {
            cnx_ctx = mediatest_create_cnx_context((mediatest_ctx_t*)callback_ctx, cnx);
            if (cnx_ctx == NULL) {
                /* cannot handle the connection */
                picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
                return -1;
            }
            else {
                cnx_ctx->is_server = 1;
                picoquic_set_callback(cnx, mediatest_callback, cnx_ctx);
            }
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Retrieve, or create and initialize stream context */
                stream_ctx = mediatest_find_or_create_stream(stream_id, cnx_ctx, 1);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void)picoquic_reset_stream(cnx, stream_id, MEDIATEST_ERROR_INTERNAL);
                ret = -1;
            }
            else {
                ret = mediatest_receive_stream_data(stream_ctx, bytes, length, (fin_or_event == picoquic_callback_stream_fin));
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
                picoquic_log_app_message(cnx, "MEDIATEST callback returns %d, event %d", ret, fin_or_event);
                DBG_PRINTF("Prepare to send on NULL context, steam: %" PRIu64, stream_id);
                ret = -1;
            }
            else {
                ret = mediatest_prepare_to_send_on_stream(stream_ctx, bytes, length, cnx_ctx->mt_ctx->simulated_time);
            }
            break;
        case picoquic_callback_datagram:
            /* Receive data in a datagram */
#if 0
            ret = mediatest_receive_datagram(cnx_ctx, bytes, length, cnx_ctx->mt_ctx->simulated_time);
#else
            ret = -1;
#endif
            break;
        case picoquic_callback_prepare_datagram:
            /* Prepare to send a datagram */
#if 0
        {
            uint64_t current_time = picoquic_get_quic_time(cnx_ctx->mt_ctx->quic);
            ret = mediatest_prepare_to_send_datagram(cnx_ctx, bytes, length, current_time);
            break;
        }
#else
            ret = -1;
            break;
#endif
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
                                             /* TODO: react to abandon stream, etc. */
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
                                                  /* Remove the connection from the context, and then delete it */
            cnx_ctx->cnx = NULL;
            mediatest_delete_cnx_context(cnx_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        case picoquic_callback_datagram_acked:
            /* Ack for packet carrying datagram-object received from peer */
        case picoquic_callback_datagram_lost:
            /* Packet carrying datagram-object probably lost */
        case picoquic_callback_datagram_spurious:
            /* Packet carrying datagram-object was not really lost */
#if 0
            ret = mediatest_handle_datagram_ack_nack(cnx_ctx, fin_or_event, stream_id /* encodes the send time!*/,
                bytes, length, picoquic_get_quic_time(cnx_ctx->mt_ctx->quic));
#else
                ret = -1;
#endif
            break;
        case picoquic_callback_pacing_changed:
            /* Notification of rate change from congestion controller */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    if (ret != 0) {
        picoquic_log_app_message(cnx, "MEDIATEST callback returns %d, event %d", ret, fin_or_event);
        DBG_PRINTF("MEDIATEST callback returns %d, event %d", ret, fin_or_event);
    }


    return ret;
}

/* Simulation step */
int mediatest_step()
{
    /* Check earliest media arrival */
    /* Check earliest packet arrival */
    /* Check earliest packet departure */
    /* Update time */
    /* Perform earliest action */
    return -1;
}

/* Test configuration */
int mediatest_configure_stream() {
    /* TODO */
    return -1;
}

void mediatest_delete_ctx(mediatest_ctx_t* mt_ctx)
{
    /* TODO */
}

mediatest_ctx_t * mediatest_configure(int do_audio, int do_video, size_t data_size, double bandwidth)
{
    int ret = 0;
    mediatest_ctx_t* mt_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }
    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        mt_ctx = (mediatest_ctx_t*)malloc(sizeof(mediatest_ctx_t));
        if (mt_ctx != NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(mt_ctx, 0, sizeof(mediatest_ctx_t));
        /* Create the QUIC contexts */
        mt_ctx->quic[0] = picoquic_create(4, NULL, NULL, test_server_cert_store_file, NULL, mediatest_callback,
            (void*)mt_ctx, NULL, NULL, NULL, mt_ctx->simulated_time, &mt_ctx->simulated_time, NULL, NULL, 0);
        mt_ctx->quic[1] = picoquic_create(4,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            MEDIATEST_ALPN, mediatest_callback, (void*)mt_ctx, NULL, NULL, NULL,
            mt_ctx->simulated_time, &mt_ctx->simulated_time, NULL, mediatest_ticket_encrypt_key, sizeof(mediatest_ticket_encrypt_key));

        if (mt_ctx->quic[0] == NULL || mt_ctx->quic[1] == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Do not use randomization by default during tests */
        for (int i = 0; i < 2; i++) {
            picoquic_set_random_initial(mt_ctx->quic[i], 0);
        }
        /* Init of the IP addresses */
        for (uint16_t i = 0; i < 2; i++) {
            picoquic_set_test_address((struct sockaddr_in*)&mt_ctx->addr[i], 0x0A000001 + i, 1234 + i);
        }
        /* register the links */
        for (int i = 0; i < 2; i++) {
            mt_ctx->link[i] = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
            if (mt_ctx->link[i] == NULL) {
                ret = -1;
                break;
            }
        }
    }
    if (ret == 0) {
        /* Create the client connection, from which media will flow. */
        mediatest_cnx_ctx_t* cnx_ctx = NULL;
        picoquic_cnx_t * cnx = picoquic_create_cnx(mt_ctx->quic[0],
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&mt_ctx->addr[1], mt_ctx->simulated_time, 0, PICOQUIC_TEST_SNI, MEDIATEST_ALPN, 1);
        /* Start the connection and create the context */
        if (cnx != NULL) {
            if (picoquic_start_client_cnx(cnx) != 0) {
                picoquic_delete_cnx(cnx);
                ret = -1;
            }
            if (cnx != NULL) {
                mt_ctx->client_cnx = mediatest_create_cnx_context(mt_ctx, cnx);
                if (mt_ctx->client_cnx == NULL) {
                    picoquic_delete_cnx(cnx);
                    ret = -1;
                }
            }
        }
    }
    if (ret == 0){
        /* Set the stream models if needed */
    }

    if (ret != 0 && mt_ctx) {
        mediatest_delete_ctx(mt_ctx);
        mt_ctx = NULL;
    }

    return mt_ctx;
}

/* One test */
int mediatest_one()
{
    /* set the configuration */
    /* Run the simulation until done */
    /* Check that the simulation ran to the end. */
    /* Check that delays meet requirements */
    return -1;
}

/* Test cases */
int mediatest_video()
{
    return -1;
}
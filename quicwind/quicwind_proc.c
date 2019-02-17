#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_START_DATA
#define WSA_START_DATA WSADATA
#endif
#ifndef WSA_START
#define WSA_START(x, y) WSAStartup((x), (y))
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picosocks.h"
#include "util.h"
#include "h3zero.c"
#include "democlient.h"

static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";

/* Message queue function, required for UI display */
void winquic_message(TCHAR * message)
{

}

/* Callback function 
 * TODO: remove the "queue of docs" logic, replace with UI requests.
 * TODO: remove fprintf(), replace by message queue. 
 * TODO: support multiple parallel connections. 
 * TODO: add state evaluation */

typedef struct st_quicwind_stream_desc_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    char const* doc_name;
    char const* f_name;
    int is_binary;
} quicwind_stream_desc_t;

#define PICOQUIC_DEMO_STREAM_LIST_MAX 16

typedef struct st_quicwind_stream_ctx_t quicwind_stream_ctx_t;

typedef struct st_quicwind_stream_ctx_t {
    quicwind_stream_ctx_t* next_stream;
    h3zero_data_stream_state_t stream_state;
    size_t received_length;
    size_t scenario_index;
    uint64_t stream_id;
    FILE* F; /* NULL if stream is closed. */
} quicwind_stream_ctx_t;

typedef struct st_quicwind_callback_ctx_t {
    quicwind_stream_ctx_t* first_stream;
    quicwind_stream_desc_t const * demo_stream;
    picoquic_tp_t const * tp;
    uint64_t last_interaction_time;

    size_t nb_demo_streams;

    int nb_open_streams;
    uint32_t nb_client_streams;

    picoquic_alpn_enum alpn;

    int progress_observed;
} quicwind_callback_ctx_t;

static quicwind_stream_ctx_t* quicwind_find_stream(
    quicwind_callback_ctx_t* ctx, uint64_t stream_id)
{
    quicwind_stream_ctx_t * stream_ctx = ctx->first_stream;

    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    return stream_ctx;
}

int quicwind_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    int ret = 0;
    uint64_t fin_stream_id = PICOQUIC_DEMO_STREAM_ID_INITIAL;

    quicwind_callback_ctx_t* ctx = (quicwind_callback_ctx_t*)callback_ctx;
    quicwind_stream_ctx_t* stream_ctx;

    ctx->last_interaction_time = picoquic_get_quic_time(cnx->quic);
    ctx->progress_observed = 1;

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        /* TODO: parse the frames. */
        /* TODO: check settings frame */
        stream_ctx = quicwind_find_stream(ctx, stream_id);
        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            if (length > 0) {
                switch (ctx->alpn) {
                case picoquic_alpn_http_3: {
                    uint16_t error_found = 0;
                    size_t available_data = 0;
                    uint8_t * bytes_max = bytes + length;
                    while (bytes < bytes_max) {
                        bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->stream_state, &available_data, &error_found);
                        if (bytes == NULL) {
                            ret = picoquic_close(cnx, error_found);
                            break;
                        }
                        else if (available_data > 0) {
                            ret = (fwrite(bytes, 1, available_data, stream_ctx->F) > 0) ? 0 : -1;
                            stream_ctx->received_length += available_data;
                            bytes += available_data;
                        }
                    }
                    break;
                }
                case picoquic_alpn_http_0_9:
                default:
                    ret = (fwrite(bytes, 1, length, stream_ctx->F) > 0) ? 0 : -1;
                    stream_ctx->received_length += length;
                    break;
                }
            }

            if (fin_or_event == picoquic_callback_stream_fin) {
                fclose(stream_ctx->F);
                stream_ctx->F = NULL;
                ctx->nb_open_streams--;
                fin_stream_id = stream_id;
                fprintf(stdout, "Stream %d ended after %d bytes\n",
                    (int)stream_id, (int)stream_ctx->received_length);
            }
        }
        break;
    case picoquic_callback_stream_reset: /* Server reset stream #x */
    case picoquic_callback_stop_sending: /* Server asks client to reset stream #x */
        /* TODO: special case for uni streams. */
        stream_ctx = quicwind_find_stream(ctx, stream_id);
        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
            ctx->nb_open_streams--;
            fin_stream_id = stream_id;
        }
        picoquic_reset_stream(cnx, stream_id, 0);
        /* TODO: higher level notify? */
        break;
    case picoquic_callback_stateless_reset:
        fprintf(stdout, "Received a stateless reset.\n");
        break;
    case picoquic_callback_close: /* Received connection close */
        fprintf(stdout, "Received a request to close the connection.\n");
        break;
    case picoquic_callback_application_close: /* Received application close */
        fprintf(stdout, "Received a request to close the application.\n");
        break;
    case picoquic_callback_stream_gap:
        /* Gap indication, when unreliable streams are supported */
        fprintf(stdout, "Received a gap indication.\n");
        stream_ctx = quicwind_find_stream(ctx, stream_id);
        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
            ctx->nb_open_streams--;
            fin_stream_id = stream_id;
        }
        /* TODO: Define what error. Stop sending? */
        picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
        break;
    case picoquic_callback_prepare_to_send:
        /* Used for active streams -- never used on client */
        break;
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        break;
    default:
        /* unexpected */
        break;
    }
    /* TODO: start streams only from console interactions. */
#if 0
    if (ret == 0 && fin_stream_id != PICOQUIC_DEMO_STREAM_ID_INITIAL) {
        /* start next batch of streams! */
        ret = quicwind_start_streams(cnx, ctx, fin_stream_id);
    }
#endif

    /* that's it */
    return ret;
}

/* Start the protocol thread upon launching the application. */
void quicwind_launch_threads()
{
    // Use CreateThread() in windows to start the protocol thread in the background.
}

/* Start a new connection */

/* Ask for a file */
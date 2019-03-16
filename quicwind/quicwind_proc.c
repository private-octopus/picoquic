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
static int quicwind_is_closing = 0;

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

    if (ctx == NULL) {
        return -1;
    }

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
                AppendText(_T("Stream ended\r\n"));
                /*
                fprintf(stdout, "Stream %d ended after %d bytes\n",
                    (int)stream_id, (int)stream_ctx->received_length);*/
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
        AppendText(_T("Received a stateless reset.\n"));
        break;
    case picoquic_callback_close: /* Received connection close */
        AppendText(_T("Received a request to delete the connection.\n"));
        picoquic_set_callback(cnx, NULL, NULL);
        free(ctx);
        break;
    case picoquic_callback_application_close: /* Received application close */
        AppendText(_T("Received a request to close the application.\n"));
        break;
    case picoquic_callback_stream_gap:
        /* Gap indication, when unreliable streams are supported */
        AppendText(_T("Received a gap indication.\r\n"));
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
        AppendText(_T("Connection Almost Ready.\n"));
        break;
    case picoquic_callback_ready:
        AppendText(_T("Connection Ready.\n"));
        break;
    default:
        /* unexpected */
        AppendText(_T("Callback unexpected.\n"));
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

/* Create the client context */
picoquic_quic_t* quicwind_create_context(const char * alpn, int mtu_max, const char * root_crt, uint8_t client_cnx_id_length)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    SOCKET_TYPE fd = INVALID_SOCKET;
    int server_addr_length = 0;
    size_t send_length = 0;
    uint64_t key_update_done = 0;
    uint64_t current_time = 0;
    int client_ready_loop = 0;
    int client_receive_loop = 0;
    int established = 0;
    int is_name = 0;
    int migration_started = 0;
    int address_updated = 0;
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;

    /* Create QUIC context */
    current_time = picoquic_current_time();
    callback_ctx.last_interaction_time = current_time;

    if (ret == 0) {
        qclient = picoquic_create(8, NULL, NULL, root_crt, alpn, NULL, NULL, NULL, NULL, NULL, current_time, NULL, ticket_store_filename, NULL, 0);

        picoquic_set_default_congestion_algorithm(qclient, picoquic_cubic_algorithm);

        if (picoquic_load_tokens(&qclient->p_first_token, current_time, token_store_filename) != 0) {
            AppendText(_T("Could not load tokens.\r\n"));
        }

        if (qclient == NULL) {
            ret = -1;
        }
        else {
            qclient->mtu_max = mtu_max;

            (void)picoquic_set_default_connection_id_length(qclient, client_cnx_id_length);

            if (root_crt == NULL) {

                /* Standard verifier would crash */
                AppendText(_T("No root crt list specified, certificate will not be verified.\r\n"));
                picoquic_set_null_verifier(qclient);
            }

        }
    }

    return qclient;
}

/* Start the protocol thread upon launching the application.
 * The background thread creates sockets, creates a client context,
 * and then loops onto connections until it is time to break.
 * At that point, it will exit the wait loop and close everything. */

DWORD WINAPI quicwind_background_thread(LPVOID lpParam)
{
    int ret = 0;
    struct sockaddr_storage packet_from;
    struct sockaddr_storage packet_to;
    socklen_t from_length;
    socklen_t to_length;
    int bytes_recv;
    unsigned long if_index_to;
    int server_addr_length = 0;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    picoquic_server_sockets_t sockets;
    const int socket_family[2] = { AF_INET6, AF_INET};
    uint64_t current_time = 0;
    picoquic_stateless_packet_t* sp;
    int client_receive_loop = 0;
    uint64_t loop_time = 0;
    int address_updated = 0;
    int64_t delay_max = 100000;
    int64_t delta_t = 0;
    size_t client_sc_nb = 0;
    picoquic_demo_stream_desc_t * client_sc = NULL;
    picoquic_quic_t* qclient = (picoquic_quic_t*)lpParam;

    /* Open sockets */
    memset(&sockets, 0, sizeof(picoquic_server_sockets_t));

    _Analysis_assume_(PICOQUIC_NB_SERVER_SOCKETS == 2);

    for (int i=0; ret == 0 && i<2; i++){
        sockets.s_socket[i] = picoquic_open_client_socket(socket_family[i]);
        if (sockets.s_socket[i] == INVALID_SOCKET) {
            ret = -1;
        }
    }

    /* Wait for packets */
    while (ret == 0) {
        unsigned char received_ecn;

        from_length = to_length = sizeof(struct sockaddr_storage);

        bytes_recv = picoquic_select(sockets.s_socket, 2, &packet_from, &from_length,
            &packet_to, &to_length, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t,
            &current_time);

        if (quicwind_is_closing) {
            break;
        }

#if 0
        if (bytes_recv != 0 && to_length != 0) {
            /* Keeping track of the addresses and ports, as we
             * need them to verify the migration behavior */
            if (!address_updated) {
                struct sockaddr_storage local_address;
                if (picoquic_get_local_address(fd, &local_address) != 0) {
                    memset(&local_address, 0, sizeof(struct sockaddr_storage));
                }

                address_updated = 1;
                picoquic_store_addr(&client_address, (struct sockaddr *)&packet_to);
                if (client_address.ss_family == AF_INET) {
                    ((struct sockaddr_in *)&client_address)->sin_port =
                        ((struct sockaddr_in *)&local_address)->sin_port;
                }
                else {
                    ((struct sockaddr_in6 *)&client_address)->sin6_port =
                        ((struct sockaddr_in6 *)&local_address)->sin6_port;
                }
                fprintf(F_log, "Local address updated\n");
            }


            if (client_address.ss_family == AF_INET) {
                ((struct sockaddr_in *)&packet_to)->sin_port =
                    ((struct sockaddr_in *)&client_address)->sin_port;
            }
            else {
                ((struct sockaddr_in6 *)&packet_to)->sin6_port =
                    ((struct sockaddr_in6 *)&client_address)->sin6_port;
            }
        }
#endif

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            if (bytes_recv > 0) {
                AppendText(_T("Packet received\r\n"));
                /* Submit the packet to the client */
                ret = picoquic_incoming_packet(qclient, buffer,
                    (size_t)bytes_recv, (struct sockaddr*)&packet_from,
                    (struct sockaddr*)&packet_to, if_index_to, received_ecn,
                    current_time);
                client_receive_loop++;
                delta_t = 0;
            }

            /* In normal circumstances, the code waits until all packets in the receive
             * queue have been processed before sending new packets. However, if the server
             * is sending lots and lots of data this can lead to the client not getting
             * the occasion to send acknowledgements. The server will start retransmissions,
             * and may eventually drop the connection for lack of acks. So we limit
             * the number of packets that can be received before sending responses. */

            if (bytes_recv == 0 || (ret == 0 && client_receive_loop > 64)) {
                picoquic_cnx_t * cnx_next = NULL;

                client_receive_loop = 0;

                if (ret == 0) {

                    send_length = PICOQUIC_MAX_PACKET_SIZE;

                    while ((sp = picoquic_dequeue_stateless_packet(qclient)) != NULL) {
                        (void)picoquic_send_through_server_sockets(&sockets,
                            (struct sockaddr*)&sp->addr_to,
                            (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            (struct sockaddr*)&sp->addr_local,
                            (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            sp->if_index_local,
                            (const char*)sp->bytes, (int)sp->length);

                        /* TODO: log stateless packet */

                        fflush(stdout);

                        picoquic_delete_stateless_packet(sp);
                    }

                    while (ret == 0 && !quicwind_is_closing && (cnx_next = picoquic_get_earliest_cnx_to_wake(qclient, current_time)) != NULL) {
                        int peer_addr_len = 0;
                        struct sockaddr_storage peer_addr;
                        int local_addr_len = 0;
                        struct sockaddr_storage local_addr;

                        if (!cnx_next->context_complete) {
                            /* Avoid processing a connection if it is not ready */
                            break;
                        }

                        ret = picoquic_prepare_packet(cnx_next, current_time,
                            send_buffer, sizeof(send_buffer), &send_length,
                            &peer_addr, &peer_addr_len, &local_addr, &local_addr_len);

                        if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                            ret = 0;

                            picoquic_delete_cnx(cnx_next);

                            fflush(stdout);

                            break;
                        }
                        else if (ret == 0) {

                            if (send_length > 0) {

                                (void)picoquic_send_through_server_sockets(&sockets,
                                    (struct sockaddr *)&peer_addr, peer_addr_len, (struct sockaddr *)&local_addr, local_addr_len,
                                    picoquic_get_local_if_index(cnx_next),
                                    (const char*)send_buffer, (int)send_length);

                                AppendText(_T("Packet sent\r\n"));
                            }
                        }
                        else {
                            break;
                        }
                    }
                }

                delta_t = picoquic_get_next_wake_delay(qclient, current_time, delay_max);
            }
        }
    }

    picoquic_close_server_sockets(&sockets);

    return ret;
}

/* Start a new connection.
 * Create a connection in the client context,
 * set addresses, etc. Add a first stream if needed.
 */
int quicwind_start_connection(picoquic_quic_t * qclient,
    char const * name, char const *port_number, char const * doc_name,
    char const * alpn, char const *sni)
{

    int ret = 0;
    int port = 443;
    struct sockaddr_storage server_address;
    int server_addr_length = 0;
    int is_name = 0;
    picoquic_cnx_t * cnx_client = NULL;

    if (qclient == NULL) {
        ret = -1;
    } else if (port_number != NULL) {
        port = atoi(port_number);
        if (port <= 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = picoquic_get_server_address(name, port, &server_address, &server_addr_length, &is_name);
        if (sni == NULL && is_name != 0) {
            sni = name;
        }
    }
    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&server_address, picoquic_get_quic_time(qclient),
            0xFF000012, sni, alpn, 1);

        if (cnx_client == NULL) {
            ret = -1;
        }
        else {
            /* TODO: create callback context! */
            quicwind_callback_ctx_t * ctx = (quicwind_callback_ctx_t *)malloc(sizeof(quicwind_callback_ctx_t));
            if (ctx == NULL) {
                ret = -1;
            }
            else {
                memset(ctx, 0, sizeof(quicwind_callback_ctx_t));

                picoquic_set_callback(cnx_client, quicwind_callback, ctx);

                ret = picoquic_start_client_cnx(cnx_client);

                if (ret == 0 && doc_name != 0) {
                    /* TODO: Start the download scenario */
                }
            }
        }
    }

    return ret;
}

/* Get a connection list, at it to the menu item */
int quicwind_get_cnx_list(picoquic_quic_t * qclient, HWND hDlg, int list_box_id)
{
    
    // Add items to list. 
    HWND hwndList = GetDlgItem(hDlg, list_box_id);
    picoquic_cnx_t * cnx = picoquic_get_first_cnx(qclient);
    int nb_cnx = 0;
    int pos;

    while (cnx != NULL) {
        int cid = 0;
        for (int x = 0; x < cnx->initial_cnxid.id_len && x < 4; x++) {
            cid <<= 8;
            cid |= cnx->initial_cnxid.id[x];
        }
        pos = (int)SendMessageA(hwndList, LB_ADDSTRING, 0,(LPARAM)cnx->sni);
        SendMessageA(hwndList, LB_SETITEMDATA, pos, (LPARAM)cid);
        nb_cnx++;
        cnx = cnx->next_in_table;
    }

    if (nb_cnx > 0){
        // Set input focus to the list box.
        SetFocus(hwndList);
    }

    return nb_cnx;
}

picoquic_cnx_t * quicwind_find_cid(picoquic_quic_t * qclient, int sel_cid)
{
    picoquic_cnx_t * cnx = picoquic_get_first_cnx(qclient);

    while (cnx != NULL) {
        int cid = 0;
        for (int x = 0; x < cnx->initial_cnxid.id_len && x < 4; x++) {
            cid <<= 8;
            cid |= cnx->initial_cnxid.id[x];
        }

        if (cid == sel_cid) {
            break;
        }
        
        cnx = cnx->next_in_table;
    }

    return cnx;
}

/* Ask to load a file, for the selected connection */
int quicwind_load_file(picoquic_quic_t * qclient, int sel_cid, char const * doc_name)
{
    int ret = 0;
    picoquic_cnx_t * cnx = quicwind_find_cid(qclient, sel_cid);

    if (cnx == NULL) {
        ret = -1;
    }
    else {
        /* Request to load the file */
    }

    return ret;
}

/* Ask to close a connection */
int quicwind_disconnect(picoquic_quic_t * qclient, int sel_cid)
{
    int ret = 0;
    picoquic_cnx_t * cnx = quicwind_find_cid(qclient, sel_cid);

    if (cnx == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_close(cnx, 0);
    }

    return ret;

}

/* Close the process */
void quicwind_orderly_exit(picoquic_quic_t * qclient, HANDLE qclient_thread, DWORD dw_qclient_thread_id)
{
    /* Need to orderly stop the client thread. */
    if (qclient_thread != NULL) {
        /* Set the global close thread flag */
        quicwind_is_closing = 1;
        /* Wait until background thread has terminated, or 3 seconds. */
        if (WaitForMultipleObjects(1, &qclient_thread, TRUE, 3000) == WAIT_TIMEOUT) {
            TerminateThread(qclient_thread, 0);
        }
        /* Close the thread handle */
        CloseHandle(qclient_thread);
    }
    if (qclient != NULL) {
        picoquic_free(qclient);
    }
}
/* PQ Bench. 
* Stand alone exe. 
* Either run as qperf server, or a qperf client.
* If a qperf client, should be capable of running multiple clients in parallel.
* All clients run the same qperf scenarion.
*/

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_config.h>
#include <picoquic_packet_loop.h>
#include <picoquic_internal.h>
#include <autoqlog.h>
#include <quicperf.h>
#include <performance_log.h>

/* Server port is first 4 hex digits of
/* MD5("PICOQUIC QPERF BENCH SERVER PORT")
/* 2214774391762663187258f8a4719ba1*/
#define PQBENCH_DEFAULT_SERVER_PORT 8724 /* 0x2214 */

void usage()
{
    fprintf(stderr, "Usage: pqbench [arguments] [ server nb_clients qperf_scenario ]\n");
    fprintf(stderr, "   nb_clients: number of parallel connections\n");
    fprintf(stderr, "   qperf_scenario: as in qperf documentation\n");
    fprintf(stderr, "Arguments are same as picoquic demo.\n");
    fprintf(stderr, "server, nb_clients and qperf_scenario only present on client\n");
    fprintf(stderr, "If present, pqbench will start nb_clients connections to the\n");
    fprintf(stderr, "server, and run the pqbench scenario on each one.\n");
}

int pqb_server(picoquic_quic_config_t* config);
int pqb_client(picoquic_quic_config_t* config, char const* server_name, int server_port,
    int nb_clients, char const* scenario);
int pqb_locate_default_file(char const** param, char const* default_file_name);

int main(int argc, char ** argv)
{
    picoquic_quic_config_t config;
    char option_string[512];
    int opt;
    const char* server_name = NULL;
    int server_port = 0;

    char* qperf_scenario = NULL;
    int is_client = 0;
    int nb_clients = 0;
    int ret;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    picoquic_register_all_congestion_control_algorithms();
    picoquic_config_init(&config);
    memcpy(option_string, "S:", 2);
    ret = picoquic_config_option_letters(option_string + 7, sizeof(option_string) - 7, NULL);

    if (ret == 0) {
        /* Get the parameters */
        while ((opt = getopt(argc, argv, option_string)) != -1) {
            switch (opt) {
            case 'S':
                picoquic_set_solution_dir(optarg);
                break;
            default:
                if (picoquic_config_command_line(opt, &optind, argc, (char const**)argv, optarg, &config) != 0) {
                    usage();
                }
                break;
            }
        }
    }

    if (optind == argc) {
        is_client = 0;
        /* Get the server key, server port, server cert
         * from the configuration.
         * If not set, use the test certificate and key
         */
        if ((ret = pqb_locate_default_file(&config.server_cert_file, PICOQUIC_TEST_FILE_SERVER_CERT)) == 0 &&
            (ret = pqb_locate_default_file(&config.server_key_file, PICOQUIC_TEST_FILE_SERVER_KEY)) == 0) {
            ret = pqb_server(&config);
        }
    }
    else if (optind + 3 == argc) {
        /* Well formed request */
        is_client = 1;
        server_name = argv[optind];
        nb_clients = atoi(argv[optind+1]);
        qperf_scenario = argv[optind+2];
        ret = pqb_client(&config, server_name, server_port, nb_clients, qperf_scenario);
    }
    else {
        usage();
        ret = -1;
    }

    picoquic_config_clear(&config);
}

/* If cert or key is missing, fill in the test value.
 */

int pqb_locate_default_file(char const ** param, char const * default_file_name)
{
    int ret = 0;
    if (*param == NULL) {
        char default_file[512];
        fprintf(stderr, "Server certificate not specified, using default.\n");
        ret = picoquic_get_input_path(default_file, sizeof(default_file), picoquic_solution_dir, default_file_name);
        if (ret == 0 &&
            (*param = picoquic_string_duplicate(default_file)) == NULL) {
            ret = -1;
        }
        if (ret != 0) {
            fprintf(stderr, "Could not find <%s> in <%s>\n", default_file_name, picoquic_solution_dir);
        }
    }
    return ret;
}


/*
* server loop callback.
* We manage an exit condition, based on the number of connections
* that we expect. The condition is activated on the first connection
* that succeeds, and triggers an exit if there are no connection
* left after that.
*/

typedef struct st_pqb_callback_t {
    int is_client;
    int nb_connections_max;
    int nb_clients;
    int nb_closed;
    int connection_done;
    picoquic_cnx_t** cnx_table;
    quicperf_ctx_t** qperf_table;
} pqb_callback_t;

static int server_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* callback_arg)
{
    int ret = 0;
    pqb_callback_t* pqb_ctx = (pqb_callback_t*)callback_ctx;

    if (pqb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }

        if (ret == 0) {
            if (pqb_ctx->is_client) {
                while (pqb_ctx->nb_closed < pqb_ctx->nb_clients) {
                    if (pqb_ctx->cnx_table[pqb_ctx->nb_closed] == NULL ||
                        pqb_ctx->cnx_table[pqb_ctx->nb_closed]->cnx_state >= picoquic_state_disconnected) {
                        pqb_ctx->nb_closed++;
                    }
                    else {
                        break;
                    }
                }
                if (pqb_ctx->nb_closed >= pqb_ctx->nb_clients) {
                    ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                }
            }
            else {
                if (pqb_ctx->nb_connections_max == 0 && picoquic_get_first_cnx(quic) != NULL) {
#ifdef PICOQUIC_MEMORY_LOG
                    if (memlog_init(picoquic_get_first_cnx(quic), 1000000, "./memlog.csv") != 0) {
                        fprintf(stderr, "Could not initialize memlog as ./memlog.csv\n");
                    }
                    else {
                        fprintf(stdout, "Initialized memlog as ./memlog.csv\n");
                    }
#endif
                    pqb_ctx->nb_connections_max = 1;
                    fprintf(stdout, "First connection noticed.\n");
                }
                else if (pqb_ctx->nb_connections_max > 0 && picoquic_get_first_cnx(quic) == NULL) {
                    fprintf(stdout, "No more active connections.\n");
                    pqb_ctx->connection_done = 1;
                    ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                }
            }
        }
    }
    return ret;
}

/*
* Simple qperf server.
*/

typedef struct st_pqbench_iovec_t {
    uint8_t* base;
    size_t len;
} ptls_pqbench_t;

/* Callback from the TLS stack upon receiving a list of proposed ALPN in the Client Hello */
size_t pqb_server_callback_select_alpn(picoquic_quic_t* quic, ptls_iovec_t* ptls_list, size_t count)
{
    size_t ret = count;
    picoquic_cnx_t* cnx = quic->cnx_in_progress;
    ptls_pqbench_t* list = (ptls_pqbench_t*)ptls_list;

    for (size_t i = 0; i < count; i++) {
        if ((const char*)list[i].base != NULL &&
            list[i].len == QUICPERF_ALPN_LEN &&
            memcmp(list[i].base, QUICPERF_ALPN, QUICPERF_ALPN_LEN) == 0) {
            ret = i;
            picoquic_set_callback(cnx, quicperf_callback, NULL);
            break;
        }
    }

    return ret;
}

int pqb_server(picoquic_quic_config_t* config)
{
    uint16_t server_port = config->server_port;
    picoquic_quic_t* qserver;
    pqb_callback_t pqb_cb_ctx = { 0 };
    int ret = 0;

    if (server_port == 0) {
        server_port = PQBENCH_DEFAULT_SERVER_PORT;
    }
    /*
    * Configure the QUIC context of the server, based on
    * configuration parameters
    */
    qserver = picoquic_create_and_configure(config, NULL,
        NULL, picoquic_current_time(), NULL);
    if (qserver == NULL) {
        ret = -1;
    }
    else {
        picoquic_set_key_log_file_from_env(qserver);

        picoquic_set_alpn_select_fn(qserver, pqb_server_callback_select_alpn);

        if (config->qlog_dir != NULL)
        {
            picoquic_set_qlog(qserver, config->qlog_dir);
        }
        if (config->performance_log != NULL)
        {
            ret = picoquic_perflog_setup(qserver, config->performance_log);
        }
        qserver->default_tp.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    }
    if (ret == 0) {
        ret = picoquic_packet_loop(qserver, server_port, 0, 0, 0, 0,
            server_loop_cb, (void*) & pqb_cb_ctx);
    }

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/*
* QUIC Bench client.
* - Create the context.
* - Init the required number of connections.
* - Program the scenario for each client.
* - Start the socket loop.
* - Exit the loop when all the connections are complete.
*/
int pqb_server_address(
    picoquic_quic_config_t* config, char const* server_name,
    struct sockaddr_storage* server_address,
    char const** sni)
{
    /* Server name is coded as <name>:port.
     * if name is not a valid name, we look for the -n parameter,
     * or use a default value assuming that nobody will check.
     * If the port is not specified, we use the pqbench default port.
     */
    int ret = 0;
    int is_name = 0;
    char s_name[512];

    uint16_t server_port = config->server_port;
    if (server_port == 0) {
        server_port = PQBENCH_DEFAULT_SERVER_PORT;
    }

    /* parse the name */
    for (int i = 0; server_name[i] != 0; i++) {
        if (i < 511) {
            s_name[i] = server_name[i];
            s_name[i + 1] = 0;
        }
        else {
            fprintf(stderr, "Server name is too long.\n");
            ret = -1;
            break;
        }
        if (server_name[i] == ':') {
            uint16_t p;
            s_name[i] = 0;
            p = atoi(server_name + i + 1);
            if (p < 0) {
                fprintf(stderr, "Invalid port number is: <%s>.\n", server_name);
                ret = -1;
            }
            else if (p != 0) {
                server_port = p;
            }
            break;
        }
    }
    /* resolve the address */
    if (ret == 0) {
        ret = picoquic_get_server_address(s_name, server_port, server_address, &is_name);

        if (ret != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>.\n", s_name, server_port);
        }
    }
    if (ret == 0) {
        *sni = picoquic_string_duplicate((is_name) ? s_name : "perf");
        if (*sni == NULL) {
            ret = -1;
            fprintf(stderr, "Cannot copy the sni.\n");
        }
    }
    return ret;
}

int pqb_client(picoquic_quic_config_t* config, char const* server_name, int server_port,
    int nb_clients, char const* scenario)
{
    int ret = 0;
    pqb_callback_t pqb_cb_ctx = { 0 };
    struct sockaddr_storage server_address;
    char const* sni = NULL;
    uint64_t current_time = picoquic_current_time();
    picoquic_quic_t* qclient = NULL;

    pqb_cb_ctx.is_client = 1;
    pqb_cb_ctx.nb_clients = nb_clients;
    pqb_cb_ctx.cnx_table = (picoquic_cnx_t**)malloc(
        sizeof(picoquic_cnx_t*) * (size_t)nb_clients);
    pqb_cb_ctx.qperf_table = (quicperf_ctx_t**)malloc(
        sizeof(quicperf_ctx_t*) * (size_t)nb_clients);

    if (pqb_cb_ctx.cnx_table == NULL || pqb_cb_ctx.qperf_table == NULL) {
        if (pqb_cb_ctx.cnx_table != NULL) {
            free(pqb_cb_ctx.cnx_table);
            pqb_cb_ctx.cnx_table = NULL;
        }
        if (pqb_cb_ctx.qperf_table != NULL) {
            free(pqb_cb_ctx.qperf_table);
            pqb_cb_ctx.qperf_table = NULL;
        }
        fprintf(stderr, "Cannot allocate tables of %d connections.\n", nb_clients);
        ret = -1;
    }
    else {
        memset(pqb_cb_ctx.cnx_table, 0, sizeof(picoquic_cnx_t*) * (size_t)nb_clients);
        memset(pqb_cb_ctx.qperf_table, 0, sizeof(quicperf_ctx_t*) * (size_t)nb_clients);
    }

    /* Get the server's address */
    if (ret == 0) {
        ret = pqb_server_address(config, server_name, &server_address, &sni);
    }

    /* Create a QUIC context. It could be used for many connections, but in this sample we
     * will use it for just one connection.
     * The sample code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    if (ret == 0) {
        /*
        * Configure the QUIC context of the server, based on
        * configuration parameters
        */
        qclient = picoquic_create_and_configure(config, NULL,
            NULL, picoquic_current_time(), NULL);
        if (qclient == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_key_log_file_from_env(qclient);

            if (config->qlog_dir != NULL)
            {
                picoquic_set_qlog(qclient, config->qlog_dir);
            }
            if (config->performance_log != NULL)
            {
                ret = picoquic_perflog_setup(qclient, config->performance_log);
            }
            qclient->default_tp.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        }
    }

    /* Before entering the packet loop, create as many
     * qperf client connections as necessary.
     */
    for (int i = 0; i < nb_clients && ret == 0; i++) {
        /* Create the qperf context and initiate the client connection */
        pqb_cb_ctx.qperf_table[i] = quicperf_create_ctx(scenario, stderr);
        if (pqb_cb_ctx.qperf_table[i] == NULL) {
            fprintf(stdout, "Could not get ready to run QUICPERF[%d]\n", i);
            ret = -1;
        }
        else if ((pqb_cb_ctx.cnx_table[i] = picoquic_create_cnx(qclient, picoquic_null_connection_id,
            picoquic_null_connection_id, (struct sockaddr*)&server_address, current_time,
            config->proposed_version, server_name, QUICPERF_ALPN, 1)) == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_callback(pqb_cb_ctx.cnx_table[i], quicperf_callback, pqb_cb_ctx.qperf_table[i]);
            ret = picoquic_start_client_cnx(pqb_cb_ctx.cnx_table[i]);
        }
    }

    /* Configure the loop callback to keep trace of connections. */

    if (ret == 0) {
        fprintf(stdout, "Ready to run QUICPERF\n");
        ret = picoquic_packet_loop(qclient, 0, 0, 0, 0, 0, 
            server_loop_cb, (void*)&pqb_cb_ctx);
    }

    /* Clean up! */
    if (qclient == NULL) {
        if (pqb_cb_ctx.cnx_table != NULL) {
            for (int i = 0; i < nb_clients && ret == 0; i++) {
                if (pqb_cb_ctx.cnx_table[i] != NULL) {
                    picoquic_delete_cnx(pqb_cb_ctx.cnx_table[i]);
                    pqb_cb_ctx.cnx_table[i] = NULL;
                }
            }
        }
        free(pqb_cb_ctx.cnx_table);
        pqb_cb_ctx.cnx_table = NULL;
        picoquic_free(qclient);
    }
    if (pqb_cb_ctx.qperf_table != NULL) {
        free(pqb_cb_ctx.qperf_table);
    }
    if (sni != NULL) {
        free((char*)sni);
    }

    return ret;
}

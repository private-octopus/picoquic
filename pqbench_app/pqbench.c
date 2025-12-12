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

int usage()
{
    fprintf(stderr, "Usage: pqbench [arguments] [ server nb_clients qperf_scenario ]\n");
    fprintf(stderr, "   nb_clients: number of parallel connections\n");
    fprintf(stderr, "   qperf_scenario: as in qperf documentation\n");
    fprintf(stderr, "Arguments are same as picoquic demo.\n");
    fprintf(stderr, "server, nb_clients and qperf_scenario only present on client\n");
    fprintf(stderr, "If present, pqbench will start nb_clients connections to the\n");
    fprintf(stderr, "server, and run the pqbench scenario on each one.\n")
}

int main(int argc, const char ** argv)
{
    picoquic_quic_config_t config;
    char option_string[512];
    int opt;
    const char* server_name = NULL;
    int server_port = 0;
    char default_server_cert_file[512];
    char default_server_key_file[512];
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
    memcpy(option_string, "A:u:f:1", 7);
    ret = picoquic_config_option_letters(option_string + 7, sizeof(option_string) - 7, NULL);

    if (ret == 0) {
        /* Get the parameters */
        while ((opt = getopt(argc, argv, option_string)) != -1) {
            continue;
        }
    }

    /* Simplified style params */
    if (optind == argc) {
        is_client = 0;
    }
    else if (optind + 3 == argc) {
        /* Well formed request */
        is_client = 1;
        server_name = argv[optind];
        nb_clients = atoi(argv[optind]+1);
        qperf_scenario = argv[optind+2];
    }
    else {
        usage();
        ret = -1;
    }
}

/*
* Simple qperf server.
*/

int pqb_server(picoquic_quic_config_t* config)
{

}


int pqb_client(char const* server_name, int server_port, char const* default_dir,
    int nb_files, char const** file_names)
{
    int ret = 0;

    return ret;
}

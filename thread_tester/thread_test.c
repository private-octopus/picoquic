#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2def.h>
#include <ws2tcpip.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif
#else
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
/* #include "picoquic_packet_loop.h" */
/* #include "picoquic_unified_log.h" */

/* Thread context, passed as parameter when starting network thread */
#define NB_THREAD_TEST_MSG 100
#define NB_THREAD_TEST_EVENT 100
#define ERROR_THREAD_TEST_MESSAGE 1
#define ERROR_THREAD_TEST_DUPLICATE 2
typedef struct st_thread_test_context_t {
#ifdef _WINDOWS

#else
#endif
    int should_stop;
    struct sockaddr_in network_thread_addr;
    int network_thread_addr_len;
    uint64_t msg_sent_at[NB_THREAD_TEST_MSG];
    uint64_t msg_recv_at[NB_THREAD_TEST_MSG];
    uint64_t event_sent_at[NB_THREAD_TEST_EVENT];
    uint64_t event_recv_at[NB_THREAD_TEST_EVENT];
    int event_sent_count;
    int event_seen_count;
    int message_error;
    uint64_t message_number_error;
    uint64_t network_exit_time;
    int message_loop_error;
    uint64_t message_loop_error_index;
    uint64_t message_loop_exit_time;


} thread_test_context_t;

/* Wakeup function */
void network_wake_up()
{
}

/* Network thread */
DWORD WINAPI network_thread(LPVOID lpParam)
{
    thread_test_context_t* ctx = (thread_test_context_t*)lpParam;
#ifdef _WINDOWS
    picoquic_recvmsg_async_ctx_t* recv_ctx;
#else
    SOCKET_TYPE n_socket;
#endif
    uint64_t current_time = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    /* Create a socket */
    /* Create an event */

    /* Loop on wait for socket or event */
    while (!ctx->should_stop) {
        int receive_ready = 0;
        uint64_t message_number = 0;
        /* wait for socket or event */
#ifdef _WINDOWS
        DWORD ret_event = WSAWaitForMultipleEvents(nb_sockets, events, FALSE, delta_t_ms, TRUE);
#else
#endif
        /* get time */
        /* if event received */
        while (ctx->event_seen_count < ctx->event_sent_count) {
            ctx->event_recv_at[ctx->event_seen_count] = current_time;
            ctx->event_seen_count++;
        }
        /* if receive ready */
        if (receive_ready) {
            /* On windows, receive async */
            /* On linux, receive socket message */
            /* Get the new time */
            current_time = picoquic_current_time();
            /* Get the message number */
            message_number = PICOPARSE_64(buffer);
            if (message_number > NB_THREAD_TEST_MSG) {
                DBG_PRINTF("Unexpected message number: %" PRIx64, message_number);
                ctx->message_error = ERROR_THREAD_TEST_MESSAGE;
                ctx->message_number_error = message_number;
                break;
            }
            else if (ctx->msg_recv_at[message_number] != 0) {
                DBG_PRINTF("Unexpected message number: %" PRIx64 ", first: %" PRIu64 ", then: %" PRIu64, 
                    message_number, ctx->msg_recv_at[message_number], current_time);
                ctx->message_error = ERROR_THREAD_TEST_DUPLICATE;
                ctx->message_number_error = message_number;
                break;
            }
            else {
                ctx->msg_recv_at[message_number] = current_time;
            }  
        }
    }
    ctx->should_stop = 1;
    ctx->network_exit_time = current_time;
    /* Close the socket */
    /* Close the event handle if needed */
    return 0;
}

/* Network loop thread -- socket only */
DWORD WINAPI network_loop_thread(LPVOID lpParam)
{
    thread_test_context_t* ctx = (thread_test_context_t*)lpParam;
    SOCKET_TYPE l_socket;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t current_time;

    memset(buffer, 0, sizeof(buffer));
    /* Create a socket */
    /* Loop on send to socket */
    for (uint64_t i = 0; i < NB_THREAD_TEST_MSG && !ctx->should_stop; i++)
    {
        int ret = 0;
        /* Wait some amount of time */
        sleep(0);
        current_time = picoquic_current_time();
        /* send the message */
        picoformat_64(i, buffer);
        ret = (int)sendto(l_socket, buffer, PICOQUIC_MAX_PACKET_SIZE,
            0, (struct sockaddr*)&ctx->network_thread_addr, ctx->network_thread_addr_len);
        if (ret != PICOQUIC_MAX_PACKET_SIZE) {
            /* Error. Document and exit */
            DBG_PRINTF("Network loop returns %d (0x%x)", ret, ret);
            ctx->message_loop_error = ret;
            ctx->message_loop_error_index = i;
            break;
        }
        else {
            ctx->msg_sent_at[i] = current_time;
        }
    }
    ctx->message_loop_exit_time = picoquic_current_time();
    /* Close the socket */
    /* exit the thread */
}

/* Event loop thread -- event only */
DWORD WINAPI event_loop_thread(LPVOID lpParam)
{
    thread_test_context_t* ctx = (thread_test_context_t*)lpParam;
    SOCKET_TYPE n_socket;
    /* Create a socket */
    /* Loop on send to socket */
    /* Close the socket */
    /* exit the thread */
}

int main(int argc, char ** argv)
{
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    printf("testing the thread execution\n");
    printf("thread1: backgroud thread, listens to a socket and to interrupts.");
    printf("thread2: backgroud thread, Wakes up the main thread at random intervals.");
    printf("thread3: network thread, sends at random intervals.");
}

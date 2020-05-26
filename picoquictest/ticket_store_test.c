/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>

static char const* test_ticket_file_name = "ticket_store_test.bin";
static char const* test_token_file_name = "token_store_test.bin";
static char const* test_sni[] = { "example.com", "example.net", "test.example.com" };
static char const* test_alpn[] = { "hq05", "hq07", "hq09" };
static const size_t nb_test_sni = sizeof(test_sni) / sizeof(char const*);
static const size_t nb_test_alpn = sizeof(test_alpn) / sizeof(char const*);
static picoquic_tp_t test_tp = {
    123, 456, 78, 91011, 1234, 567, 0, 0, 0, 0, 0, 0,
    { 0, {0,0,0,0}, 0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0,
        {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0},
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}
};

static int create_test_ticket(uint64_t current_time, uint32_t ttl, uint8_t* buf, uint16_t len)
{
    int ret = 0;
    if (len < 35) {
        ret = -1;
    } else {
        uint16_t t_length = len - 31;
        picoformat_64(buf, current_time);
        buf[8] = 0;
        buf[9] = 1;
        buf[10] = 0;
        buf[11] = (uint8_t)(t_length >> 8);
        buf[12] = (uint8_t)(t_length & 0xFF);
        picoformat_32(buf + 13, ttl);
        memset(buf + 17, 0xcc, len - 17);
        buf[len - 18] = 0;
        buf[len - 17] = 16;
    }

    return ret;
}

static int ticket_store_compare(picoquic_stored_ticket_t* s1, picoquic_stored_ticket_t* s2)
{
    int ret = 0;
    picoquic_stored_ticket_t* c1 = s1;
    picoquic_stored_ticket_t* c2 = s2;

    while (ret == 0 && c1 != 0) {
        if (c2 == 0) {
            ret = -1;
        } else {
            if (c1->time_valid_until != c2->time_valid_until || c1->sni_length != c2->sni_length || c1->alpn_length != c2->alpn_length || c1->ticket_length != c2->ticket_length || memcmp(c1->sni, c2->sni, c1->sni_length) != 0 || memcmp(c1->alpn, c2->alpn, c1->alpn_length) != 0 || memcmp(c1->ticket, c2->ticket, c1->ticket_length) != 0) {
                ret = -1;
            } else {
                for (int i = 0; i < PICOQUIC_NB_TP_0RTT; i++) {
                    if (c1->tp_0rtt[i] != c2->tp_0rtt[i]) {
                        ret = -1;
                        break;
                    }
                }
                if (ret == 0) {
                    c1 = c1->next_ticket;
                    c2 = c2->next_ticket;
                }
            }
        }
    }

    if (ret == 0 && c1 == NULL && c2 != NULL) {
        ret = -1;
    }

    return ret;
}

int ticket_store_test()
{
    int ret = 0;
    picoquic_stored_ticket_t* p_first_ticket = NULL;
    picoquic_stored_ticket_t* p_first_ticket_bis = NULL;
    picoquic_stored_ticket_t* p_first_ticket_ter = NULL;
    picoquic_stored_ticket_t* p_first_ticket_empty = NULL;

    uint64_t ticket_time = 40000000000ull;
    uint64_t current_time = 50000000000ull;
    uint64_t retrieve_time = 60000000000ull;
    uint64_t too_late_time = 150000000000ull;
    uint32_t ttl = 100000;
    uint8_t ticket[128];

    /* Writing an empty file */
    ret = picoquic_save_tickets(p_first_ticket, current_time, test_ticket_file_name);

    /* Load the empty file again */
    if (ret == 0) {
        ret = picoquic_load_tickets(&p_first_ticket_empty, retrieve_time, test_ticket_file_name);

        /* Verify that the content is empty */
        if (p_first_ticket_empty != NULL) {
            if (ret == 0) {
                ret = -1;
            }
            picoquic_free_tickets(&p_first_ticket_empty);
        }
    }

    /* Generate a set of tickets */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_alpn; j++) {
            uint16_t ticket_length = (uint16_t)(64 + j * nb_test_sni + i);
            ret = create_test_ticket((ticket_time / 1000) + 1000 * ((i * nb_test_alpn) + j), ttl, ticket, ticket_length);
            if (ret != 0) {
                break;
            }
            ret = picoquic_store_ticket(&p_first_ticket, current_time,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_alpn[j], (uint16_t)strlen(test_alpn[j]),
                ticket, ticket_length, &test_tp);
            if (ret != 0) {
                break;
            }
        }
    }

    /* Verify that they can be retrieved */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_alpn; j++) {
            uint16_t ticket_length = 0;
            uint16_t expected_length = (uint16_t)(64 + j * nb_test_sni + i);
            uint8_t* ticket = NULL;
            ret = picoquic_get_ticket(p_first_ticket, current_time,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_alpn[j], (uint16_t)strlen(test_alpn[j]),
                &ticket, &ticket_length, NULL, 0);
            if (ret != 0) {
                break;
            }
            if (ticket_length != expected_length) {
                ret = -1;
                break;
            }
        }
    }
    /* Store them on a file */
    if (ret == 0) {
        ret = picoquic_save_tickets(p_first_ticket, current_time, test_ticket_file_name);
    }
    /* Load the file again */
    if (ret == 0) {
        ret = picoquic_load_tickets(&p_first_ticket_bis, retrieve_time, test_ticket_file_name);
    }

    /* Verify that the two contents match */
    if (ret == 0) {
        ret = ticket_store_compare(p_first_ticket, p_first_ticket_bis);
    }

    /* Reload after a long time */
    if (ret == 0) {
        ret = picoquic_load_tickets(&p_first_ticket_ter, too_late_time, test_ticket_file_name);

        if (ret == 0 && p_first_ticket_ter != NULL) {
            ret = -1;
        }
    }
    /* Free what needs be */
    picoquic_free_tickets(&p_first_ticket);
    picoquic_free_tickets(&p_first_ticket_bis);
    picoquic_free_tickets(&p_first_ticket_ter);

    return ret;
}

/*
 * The token store is extremely similar to the ticket store.
 */


static uint8_t const test_addr1[] = { 127, 0, 0, 1 };
static uint8_t const test_addr2[] = { 128, 12, 34, 56 };
static uint8_t const test_addr3[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static uint8_t const test_addr4[] = { 0x20, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 1 };

typedef struct st_test_token_store_addr_t {
    uint8_t const * ip_addr;
    uint8_t ip_addr_length;
} test_token_store_addr_t;

static test_token_store_addr_t test_ip_addr[] = {
    { test_addr1, (uint8_t)sizeof(test_addr1) },
    { test_addr2, (uint8_t)sizeof(test_addr2) },
    { test_addr3, (uint8_t)sizeof(test_addr3) },
    { test_addr4, (uint8_t)sizeof(test_addr4) },
};

static size_t nb_test_ip_addr = sizeof(test_ip_addr) / sizeof(test_token_store_addr_t);

static int create_test_token(uint64_t current_time, uint32_t ttl, uint8_t* buf, uint16_t len)
{
    int ret = 0;
    if (len < 35) {
        ret = -1;
    }
    else {
        uint16_t t_length = len - 31;
        picoformat_64(buf, current_time);
        buf[8] = 0;
        buf[9] = 1;
        buf[10] = 0;
        buf[11] = (uint8_t)(t_length >> 8);
        buf[12] = (uint8_t)(t_length & 0xFF);
        picoformat_32(buf + 13, ttl);
        memset(buf + 17, 0xcc, len - 17);
        buf[len - 18] = 0;
        buf[len - 17] = 16;
    }

    return ret;
}

static int token_store_compare(picoquic_stored_token_t* s1, picoquic_stored_token_t* s2)
{
    int ret = 0;
    picoquic_stored_token_t* c1 = s1;
    picoquic_stored_token_t* c2 = s2;

    while (ret == 0 && c1 != 0) {
        if (c2 == 0) {
            ret = -1;
        }
        else {
            if (c1->time_valid_until != c2->time_valid_until || c1->sni_length != c2->sni_length || 
                c1->ip_addr_length != c2->ip_addr_length || c1->token_length != c2->token_length ||
                memcmp(c1->sni, c2->sni, c1->sni_length) != 0 || 
                memcmp(c1->ip_addr, c2->ip_addr, c1->ip_addr_length) != 0 || 
                memcmp(c1->token, c2->token, c1->token_length) != 0) {
                ret = -1;
            }
            else {
                c1 = c1->next_token;
                c2 = c2->next_token;
            }
        }
    }

    if (ret == 0 && c1 == NULL && c2 != NULL) {
        ret = -1;
    }

    return ret;
}

int token_store_test()
{
    int ret = 0;
    picoquic_stored_token_t* p_first_token = NULL;
    picoquic_stored_token_t* p_first_token_bis = NULL;
    picoquic_stored_token_t* p_first_token_ter = NULL;
    picoquic_stored_token_t* p_first_token_empty = NULL;

    uint64_t token_time = 40000000000ull;
    uint64_t current_time = 50000000000ull;
    uint64_t retrieve_time = 60000000000ull;
    uint64_t too_late_time = 150000000000ull;
    uint32_t ttl = 100000;
    uint8_t token[128];

    /* Writing an empty file */
    ret = picoquic_save_tokens(p_first_token, current_time, test_token_file_name);

    /* Load the empty file again */
    if (ret == 0) {
        ret = picoquic_load_tokens(&p_first_token_empty, retrieve_time, test_token_file_name);

        /* Verify that the content is empty */
        if (p_first_token_empty != NULL) {
            if (ret == 0) {
                ret = -1;
            }
            picoquic_free_tokens(&p_first_token_empty);
        }
    }

    /* Generate a set of tokens */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_ip_addr; j++) {
            uint16_t token_length = (uint16_t)(64 + j * nb_test_sni + i);
            ret = create_test_token((token_time / 1000) + 1000 * ((i * nb_test_ip_addr) + j), ttl, token, token_length);
            if (ret != 0) {
                break;
            }
            ret = picoquic_store_token(&p_first_token, current_time,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_ip_addr[j].ip_addr, test_ip_addr[j].ip_addr_length,
                token, token_length);
            if (ret != 0) {
                break;
            }
        }
    }

    /* Verify that they can be retrieved */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_alpn; j++) {
            uint16_t token_length = 0;
            uint16_t expected_length = (uint16_t)(64 + j * nb_test_sni + i);
            uint8_t* token = NULL;
            ret = picoquic_get_token(p_first_token, current_time,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_ip_addr[j].ip_addr, test_ip_addr[j].ip_addr_length,
                &token, &token_length, 0);
            if (ret != 0) {
                break;
            }
            if (token_length != expected_length) {
                ret = -1;
                break;
            }

            if (token != NULL) {
                free(token);
                token = NULL;
            }
        }
    }
    /* Store them on a file */
    if (ret == 0) {
        ret = picoquic_save_tokens(p_first_token, current_time, test_token_file_name);
    }
    /* Load the file again */
    if (ret == 0) {
        ret = picoquic_load_tokens(&p_first_token_bis, retrieve_time, test_token_file_name);
    }

    /* Verify that the two contents match */
    if (ret == 0) {
        ret = token_store_compare(p_first_token, p_first_token_bis);
    }

    /* Reload after a long time */
    if (ret == 0) {
        ret = picoquic_load_tokens(&p_first_token_ter, too_late_time, test_token_file_name);

        if (ret == 0 && p_first_token_ter != NULL) {
            ret = -1;
        }
    }
    /* Free what needs be */
    picoquic_free_tokens(&p_first_token);
    picoquic_free_tokens(&p_first_token_bis);
    picoquic_free_tokens(&p_first_token_ter);

    return ret;
}

/* Check the protection against token reuse */
typedef struct st_token_reuse_api_case_t {
    uint64_t expiry_date;
    uint8_t token[16];
    size_t token_length;
} token_reuse_api_case_t;

static token_reuse_api_case_t token_reuse_api_cases[] = {
    { 2, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 3, { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, 12},
    { 3, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 3, { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 12},
    { 5, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 7, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 1, { 1, 2, 3, 4, 5, 6, 7, 8}, 8},
};

static size_t nb_token_reuse_api_cases = sizeof(token_reuse_api_cases) / sizeof(token_reuse_api_case_t);

int token_reuse_api_test()
{
    int ret = 0;
    uint64_t test_time = 4;
    uint64_t simulated_time = 0;
    picoquic_quic_t * quic = picoquic_create(4, NULL, NULL, NULL, "test", NULL, NULL, NULL, NULL,
        NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context");
        ret = -1;
    }
    else {
        /* Test that all tokens can be created */
        for (size_t i = 0; ret == 0 && i < nb_token_reuse_api_cases; i++) {
            if (picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[i].token,
                token_reuse_api_cases[i].token_length,
                token_reuse_api_cases[i].expiry_date) != 0) {
                DBG_PRINTF("Token[%z] already used?", i);
                ret = -1;
            }
        }
        /* Test that all tokens can be detected as in use */
        for (size_t i = 0; ret == 0 && i < nb_token_reuse_api_cases; i++) {
            if (picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[i].token,
                token_reuse_api_cases[i].token_length,
                token_reuse_api_cases[i].expiry_date) == 0) {
                DBG_PRINTF("Token[%z] not already used?", i);
                ret = -1;
            }
        }
        /* Remove tokens with t <= test_time */
        picoquic_registered_token_clear(quic, test_time);
        /* Test that all deleted tokens are absent and others are not */
        for (size_t i = 0; ret == 0 && i < nb_token_reuse_api_cases; i++) {
            int x = picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[i].token,
                token_reuse_api_cases[i].token_length,
                token_reuse_api_cases[i].expiry_date);
            if (x == 0 && token_reuse_api_cases[i].expiry_date >= test_time){
                DBG_PRINTF("Token[%z], time %" PRIu64 " not already used?", i, token_reuse_api_cases[i].expiry_date);
                ret = -1;
            }
            if (x != 0 && token_reuse_api_cases[i].expiry_date < test_time) {
                DBG_PRINTF("Token[%z], time %" PRIu64 " already used?", i, token_reuse_api_cases[i].expiry_date);
                ret = -1;
            }
        }
        /* Check refusal with length < 8 */
        for (size_t l = 0; ret == 0 && l < 8; l++) {
            if (picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[0].token, l,
                token_reuse_api_cases[0].expiry_date) == 0) {
                DBG_PRINTF("Token[1] length %z accepted?", l);
                ret = -1;
            }
        }

        picoquic_free(quic);
    }

    return ret;
}
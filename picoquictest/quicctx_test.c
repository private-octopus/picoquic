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

/*
* Direct-call tests for a handful of narrow branches in quicctx.c that are never
* exercised by the rest of the test suite -- quicctx.c is core connection-context
* infrastructure already exercised implicitly by nearly every other test (hence its
* high line/function coverage), so what remains are edge cases: out-of-range
* arguments, "not found" lookups, and small internal-state pokes.
*/

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <string.h>

int picoquic_verify_proposed_tuple(picoquic_cnx_t* cnx, struct sockaddr const** p_addr_peer,
    struct sockaddr const** p_addr_local, int* p_if_index);
int picoquic_check_new_path_allowed(picoquic_cnx_t* cnx, int to_preferred_address);

/* picoquic_context_from_epoch falls back to the application context (numeric 0)
 * for any epoch outside [0,3] -- never exercised, since every real caller passes
 * a valid epoch. */
int quicctx_context_from_epoch_test(void)
{
    int ret = 0;

    if (picoquic_context_from_epoch(-1) != picoquic_packet_context_application) {
        ret = -1;
    }
    if (ret == 0 && picoquic_context_from_epoch(4) != picoquic_packet_context_application) {
        ret = -1;
    }
    return ret;
}

/* picoquic_adjust_max_connections rejects a request to raise the limit above the
 * quic context's hard maximum -- never exercised, since every existing test only
 * lowers or matches the limit. */
int quicctx_adjust_max_connections_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else {
        if (picoquic_adjust_max_connections(quic, quic->max_number_connections + 1) == 0) {
            DBG_PRINTF("%s", "picoquic_adjust_max_connections did not reject a limit above the maximum");
            ret = -1;
        }
        picoquic_free(quic);
    }
    return ret;
}

/* picoquic_set_default_address_discovery_mode falls back to mode 0 for any value
 * outside (0,3] -- never exercised, since every existing test passes a valid mode. */
int quicctx_set_default_address_discovery_mode_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else {
        picoquic_set_default_address_discovery_mode(quic, 4);
        if (quic->default_tp.address_discovery_mode != 0) {
            ret = -1;
        }
        picoquic_free(quic);
    }
    return ret;
}

/* picoquic_is_local_cid returns false for a CID of the right length that is not
 * actually registered -- never exercised, since existing tests only check CIDs
 * that are either registered or the wrong length. */
int quicctx_is_local_cid_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else {
        picoquic_connection_id_t cid;
        memset(&cid, 0xAB, sizeof(cid));
        cid.id_len = (uint8_t)picoquic_get_local_cid_length(quic);

        if (picoquic_is_local_cid(quic, &cid) != 0) {
            DBG_PRINTF("%s", "picoquic_is_local_cid accepted an unregistered CID");
            ret = -1;
        }
        picoquic_free(quic);
    }
    return ret;
}

/* picoquic_get_path_addr's peer_addr case and its default (unknown "local" selector)
 * case were never exercised -- every existing caller only asks for the local or
 * observed address. */
int quicctx_get_path_addr_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_storage addr;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        uint64_t unique_path_id = cnx->path[0]->unique_path_id;

        if (picoquic_get_path_addr(cnx, unique_path_id, 2, &addr) != 0) {
            DBG_PRINTF("%s", "picoquic_get_path_addr failed on the peer address selector");
            ret = -1;
        }
        if (ret == 0 && picoquic_get_path_addr(cnx, unique_path_id, 9, &addr) == 0) {
            DBG_PRINTF("%s", "picoquic_get_path_addr did not reject an unknown address selector");
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* picoquic_set_stream_path_affinity's UINT64_MAX "clear affinity" branch, and its
 * "unique_path_id does not match any path" branch, were never exercised -- every
 * existing test sets affinity to a real, existing path. */
int quicctx_set_stream_path_affinity_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint8_t data[] = { 1, 2, 3, 4 };

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else if (picoquic_add_to_stream(cnx, 0, data, sizeof(data), 0) != 0) {
        ret = -1;
    }
    else {
        picoquic_stream_head_t* stream = picoquic_find_stream(cnx, 0);

        if (stream == NULL) {
            ret = -1;
        }
        else {
            stream->affinity_path = cnx->path[0];
            if (picoquic_set_stream_path_affinity(cnx, 0, UINT64_MAX) != 0 ||
                stream->affinity_path != NULL) {
                DBG_PRINTF("%s", "picoquic_set_stream_path_affinity did not clear affinity for UINT64_MAX");
                ret = -1;
            }
            if (ret == 0 && picoquic_set_stream_path_affinity(cnx, 0, cnx->path[0]->unique_path_id + 12345) == 0) {
                DBG_PRINTF("%s", "picoquic_set_stream_path_affinity did not reject an unknown path id");
                ret = -1;
            }
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* picoquic_verify_proposed_tuple rejects a peer/local address pair whose address
 * families do not match -- never exercised, since every existing test supplies a
 * consistent address family for both. */
int quicctx_verify_proposed_tuple_family_mismatch_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr const* addr_peer;
    struct sockaddr const* addr_local;
    int if_index = 0;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;

        addr_peer = (struct sockaddr const*)&addr4;
        addr_local = (struct sockaddr const*)&addr6;

        if (picoquic_verify_proposed_tuple(cnx, &addr_peer, &addr_local, &if_index) != PICOQUIC_ERROR_PATH_ADDRESS_FAMILY) {
            DBG_PRINTF("%s", "picoquic_verify_proposed_tuple did not reject mismatched address families");
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* Regression test: picoquic_probe_new_tuple used to discard the return value of
 * picoquic_verify_proposed_tuple, immediately overwriting it with the result of
 * picoquic_check_cid_for_new_tuple before ever checking it -- so a real address
 * verification failure (e.g. mismatched address families) was silently ignored.
 * Confirms the fix: the family-mismatch error now propagates out of
 * picoquic_probe_new_tuple itself. */
int quicctx_probe_new_tuple_family_mismatch_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;

        if (picoquic_probe_new_tuple(cnx, cnx->path[0], (struct sockaddr const*)&addr4,
            (struct sockaddr const*)&addr6, 0, 0, 0) != PICOQUIC_ERROR_PATH_ADDRESS_FAMILY) {
            DBG_PRINTF("%s", "picoquic_probe_new_tuple did not propagate a mismatched-address-family error");
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* picoquic_remember_issued_ticket: the oversized-ip_addr_length clamp, and the
 * fresh-ticket insertion path (as opposed to updating an already-remembered
 * ticket), were never exercised together -- existing tests only remember tickets
 * with a normal-size address, and only ever update the same ticket_id twice. */
int quicctx_remember_issued_ticket_oversized_addr_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else {
        uint8_t oversized_addr[PICOQUIC_STORED_IP_MAX + 4];
        picoquic_issued_ticket_t* ticket;

        memset(oversized_addr, 0x11, sizeof(oversized_addr));

        if (picoquic_remember_issued_ticket(quic, 0x1234567890ull, 100000, 65536,
            oversized_addr, (uint8_t)sizeof(oversized_addr)) != 0) {
            ret = -1;
        }
        else {
            ticket = picoquic_retrieve_issued_ticket(quic, 0x1234567890ull);
            if (ticket == NULL || ticket->ip_addr_length != PICOQUIC_STORED_IP_MAX) {
                DBG_PRINTF("%s", "picoquic_remember_issued_ticket did not clamp an oversized address length");
                ret = -1;
            }
        }
        picoquic_free(quic);
    }
    return ret;
}

/* picoquic_check_new_path_allowed's "too many paths already" branch was never
 * exercised -- reached by temporarily poking nb_paths past PICOQUIC_NB_PATH_TARGET
 * on a connection that is otherwise ready for path creation, then restoring it. */
int quicctx_check_new_path_allowed_limit_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        picoquic_state_enum saved_state = cnx->cnx_state;
        int saved_nb_paths = cnx->nb_paths;

        cnx->cnx_state = picoquic_state_ready;
        cnx->nb_paths = PICOQUIC_NB_PATH_TARGET;

        if (picoquic_check_new_path_allowed(cnx, 0) != PICOQUIC_ERROR_PATH_LIMIT_EXCEEDED) {
            DBG_PRINTF("%s", "picoquic_check_new_path_allowed did not reject creating a path past the limit");
            ret = -1;
        }

        cnx->cnx_state = saved_state;
        cnx->nb_paths = saved_nb_paths;
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

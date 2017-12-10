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

#include <string.h>
#include "../picoquic/picoquic_internal.h"
#include "../picoquic/tls_api.h"

static uint8_t const addr1[4] = { 10, 0, 0, 1 };
static uint8_t const addr2[4] = { 10, 0, 0, 2 };

void cleartext_aead_packet_init_header(picoquic_packet_header *ph,
    uint64_t cnx_id, uint32_t pn, uint32_t vn, picoquic_packet_type_enum ptype)
{
    ph->cnx_id = cnx_id;
    ph->pn = pn;
    ph->pn64 = pn;
    ph->vn = vn;
    ph->ptype = ptype;
    ph->offset = 17;
    ph->pnmask = 0xFFFFFFFF;
}

void cleartext_aead_init_packet(picoquic_packet_header *ph,
    uint8_t * cleartext, size_t target)
{
    size_t byte_index = 0;
    uint64_t seed = ph->cnx_id;

    seed ^= ph->pn;

    /* Serialize the header */
    cleartext[byte_index++] = 0x80 | ((uint8_t)ph->ptype);
    picoformat_64(&cleartext[byte_index], ph->cnx_id);
    byte_index += 8;
    picoformat_32(&cleartext[byte_index], ph->pn);
    byte_index += 4;
    picoformat_32(&cleartext[byte_index], ph->vn);
    byte_index += 4;
    /* Add some silly content */
    while (byte_index < target)
    {
        seed *= 101;
        cleartext[byte_index++] = (uint8_t)seed & 255;
    }
}

int cleartext_aead_test()
{
    int ret = 0;
    uint8_t clear_text[1536];
    uint8_t incoming[1536];
    uint32_t seqnum = 0xdeadbeef;
    size_t clear_length = 1200;
    size_t encoded_length;
    size_t decoded_length;
    picoquic_packet_header ph_init;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t * cnx_client = NULL;
    picoquic_cnx_t * cnx_server = NULL;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, 
        NULL, NULL, NULL);
    picoquic_quic_t * qserver = picoquic_create(8,
#ifdef _WINDOWS
        "..\\certs\\cert.pem", "..\\certs\\key.pem",
#else
        "certs/cert.pem", "certs/key.pem",
#endif
        "test", NULL, NULL, NULL, NULL, NULL);
    if (qclient == NULL || qserver == NULL)
    {
        ret = -1;
    }

    if (ret == 0)
    {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, 0,
            (struct sockaddr *)&test_addr_c, 0, 0, NULL, NULL);
        if (cnx_client == NULL)
        {
            ret = -1;
        }
    }

    if (ret == 0)
    {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, 
            (struct sockaddr *)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL);

        if (cnx_server == NULL)
        {
            ret = -1;
        }
    }

    /* Create a packet from client to server, encrypt, decrypt */
    if (ret == 0)
    {
        cleartext_aead_packet_init_header(&ph_init,
            cnx_client->initial_cnxid, seqnum, cnx_client->proposed_version,
            picoquic_packet_client_initial);
        cleartext_aead_init_packet(&ph_init, clear_text, clear_length);

        /* AEAD Encrypt, to the send buffer */
        memcpy(incoming, clear_text, ph_init.offset);
        encoded_length = picoquic_aead_cleartext_encrypt(
            cnx_client, incoming + ph_init.offset,
             clear_text + ph_init.offset, clear_length - ph_init.offset,
            seqnum, incoming, ph_init.offset);
        encoded_length += ph_init.offset;

        /* AEAD Decrypt */
        decoded_length = picoquic_decrypt_cleartext(cnx_server,
            incoming, encoded_length, &ph_init);

        if (decoded_length != clear_length)
        {
            ret = -1;
        }
        else if (memcmp(incoming, clear_text, clear_length) != 0)
        {
            ret = 1;
        }
    }

    if (cnx_client != NULL)
    {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL)
    {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL)
    {
        picoquic_free(qclient);
    }

    if (qserver != NULL)
    {
        picoquic_free(qserver);
    }

    return ret;
}


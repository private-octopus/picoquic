#ifdef WIN32
#include "wincompat.h"
#endif
#include "picotls.h"
#include "picoquic.h"

/*
 * Arrival of a handshake item (frame 0) in a packet of type T.
 * This triggers an optional progress of the connection.
 * Different processing based on packet type:
 *
 * - Client side initialization. Include transport parameters.
 *   May provide 0-RTT initialisation.
 * - Client Initial Receive. Accept the connection. Include TP.
 *   May provide 0-RTT initialization.
 *   Provide 1-RTT init.
 * - Server Clear Text. Confirm the client side connection.
 *   May provide 1-RTT init
 */

int picoquic_tlsinput(picoquic_cnx * cnx, picoquic_packet_type_enum ptype,
    uint8_t * bytes, size_t length, size_t * consumed, struct st_ptls_buffer_t * sendbuf)
{
    ptls_context_t * tls_ctx = (ptls_context_t *)cnx->tls_ctx;
    size_t inlen = 0, roff = 0;
    int ret = 0;

    ptls_buffer_init(sendbuf, "", 0);


    /* Provide the data */
    while (roff < length && (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
    {
        inlen = length - roff;
        ret = ptls_handshake(tls_ctx, sendbuf, bytes + roff, &inlen, NULL);
        roff += inlen;
    }

    *consumed = roff;

    return ret;
}
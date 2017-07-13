#include "picoquic.h"

/*
 * Sending logic.
 *
 * Data is sent over streams. This is instantiated by the "Post to stream" command, which
 * chains data to the head of stream structure. Data is unchained when it sent for the
 * first time.
 * 
 * Data is sent in packets, which contain stream frames and possibly other frames.
 * The retransmission logic operates on packets. If a packet is seen as lost, the
 * important frames that it contains will have to be retransmitted.
 *
 * Unacknowledged packets are kept in a chained list. Packets get removed from that
 * list during the processing of acknowledgements. Packets are marked lost when a
 * sufficiently older packet is acknowledged, or after a timer. Lost packets
 * generate new packets, which are queued in the chained list.
 *
 * Stream 0 is special, in the sense that it cannot be closed or reset, and is not
 * subject to flow control.
 *
 */

int picoquic_add_to_stream(picoquic_cnx * cnx, uint32_t stream_id, uint8_t * data, size_t length)
{
    int ret = 0;
    picoquic_stream_head * stream = NULL;

    /* TODO: check for other streams. */
    if (stream_id == 0)
    {
        stream = &cnx->first_stream;
    }

    if (stream == NULL)
    {
        ret = -1;
    }
    else
    {
        picoquic_stream_data * stream_data = (picoquic_stream_data *)malloc(sizeof(picoquic_stream_data));

        if (stream_data == 0)
        {
            ret = -1;
        }
        else
        {
            stream_data->bytes = (uint8_t *)malloc(length);

            if (stream_data->bytes == NULL)
            {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            }
            else
            {
                picoquic_stream_data ** pprevious = &stream->send_queue;
                picoquic_stream_data * next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL)
                {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }
    }

    return ret;
}


int picoquic_prepare_packet(picoquic_cnx * cnx, picoquic_packet * packet)
{
    /* TODO: Check for interesting streams */
    int ret = 0;
    picoquic_stream_head * stream = &cnx->first_stream;
    picoquic_packet_type_enum packet_type = 0;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state)
    {
    case picoquic_state_client_init:
        packet_type = picoquic_packet_client_initial;
        break;
    case picoquic_state_server_init:
        packet_type = picoquic_packet_server_cleartext;
        break;
    case picoquic_state_client_handshake_start: 
        packet_type = picoquic_packet_client_cleartext;
        break;
    case picoquic_state_client_handshake_progress:
        packet_type = picoquic_packet_client_cleartext;
        break;
    case picoquic_state_client_ready: 
        packet_type = picoquic_packet_1rtt_protected_phi0;
        break;
    case picoquic_state_server_handshake_progress:
        packet_type = picoquic_packet_server_stateless;
        break;
    case picoquic_state_server_ready: 
        packet_type = picoquic_packet_1rtt_protected_phi0;
        break;
    case picoquic_state_disconnected: 
        ret = -1; 
        break;
    }

    if (ret == 0)
    {
        /* Prepare the packet header */
    }
    /* Check whether ACK is needed */

    /* Encode the stream frame */

    return -1;
}
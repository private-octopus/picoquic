#include "picoquic.h"

char const* picoquic_tp_name(picoquic_tp_enum tp_number)
{
    char const* tp_name = "unknown";

    switch (tp_number) {
    case picoquic_tp_original_connection_id:
        tp_name = "original_connection_id";
        break;
    case picoquic_tp_idle_timeout:
        tp_name = "idle_timeout";
        break;
    case picoquic_tp_stateless_reset_token:
        tp_name = "stateless_reset_token";
        break;
    case picoquic_tp_max_packet_size:
        tp_name = "max_packet_size";
        break;
    case picoquic_tp_initial_max_data:
        tp_name = "initial_max_data";
        break;
    case picoquic_tp_initial_max_stream_data_bidi_local:
        tp_name = "initial_max_stream_data_bidi_local";
        break;
    case picoquic_tp_initial_max_stream_data_bidi_remote:
        tp_name = "initial_max_stream_data_bidi_remote";
        break;
    case picoquic_tp_initial_max_stream_data_uni:
        tp_name = "initial_max_stream_data_uni";
        break;
    case picoquic_tp_initial_max_streams_bidi:
        tp_name = "initial_max_streams_bidi";
        break;
    case picoquic_tp_initial_max_streams_uni:
        tp_name = "initial_max_streams_uni";
        break;
    case picoquic_tp_ack_delay_exponent:
        tp_name = "ack_delay_exponent";
        break;
    case picoquic_tp_max_ack_delay:
        tp_name = "max_ack_delay";
        break;
    case picoquic_tp_disable_migration:
        tp_name = "disable_migration";
        break;
    case picoquic_tp_server_preferred_address:
        tp_name = "server_preferred_address";
        break;
    case picoquic_tp_active_connection_id_limit:
        tp_name = "active_connection_id_limit";
        break;
    case picoquic_tp_retry_connection_id:
        tp_name = "retry_connection_id";
        break;
    case picoquic_tp_handshake_connection_id:
        tp_name = "handshake_connection_id";
        break;
    case picoquic_tp_max_datagram_frame_size:
        tp_name = "max_datagram_frame_size";
        break;
    case picoquic_tp_test_large_chello:
        tp_name = "large_chello";
        break;
    case picoquic_tp_enable_loss_bit:
        tp_name = "enable_loss_bit";
        break;
    case picoquic_tp_min_ack_delay:
        tp_name = "min_ack_delay";
        break;
    case picoquic_tp_enable_time_stamp:
        tp_name = "enable_time_stamp";
        break;
    case picoquic_tp_grease_quic_bit:
        tp_name = "grease_quic_bit";
        break;
    case picoquic_tp_version_negotiation:
        tp_name = "version_negotiation";
        break;
    case picoquic_tp_enable_bdp_frame:
        tp_name = "enable_bdp_frame";
        break;
    case picoquic_tp_initial_max_path_id:
        tp_name = "initial_max_path_id";
        break;
    case picoquic_tp_address_discovery:
        tp_name = "address_discovery";
        break;
    case picoquic_tp_reset_stream_at:
        tp_name = "reset_stream_at";
        break;
    default:
        break;
    }

    return tp_name;
}
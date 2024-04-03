#include <iostream>
#include <picoquic.h>
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include <cmath>
#include <chrono>
#include <fstream>

std::string msg(1000000000, 'a');

typedef struct st_server_app_ctx_t
{
  int last_path_id;
} server_app_ctx_t;

int sample_server_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *stream_ctx);

// int sample_server_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode,
//                           void *callback_ctx, void *callback_arg);

int main(int argc, char **argv)
{
  std::cout << "Server started" << std::endl;

  int ret = 0;
  int server_port = 12000;
  const char *server_cert = "./toy_app/ca-cert.pem";
  const char *server_key = "./toy_app/server-key.pem";
  char *default_alpn = "my_custom_alpn";
  uint64_t current_time = picoquic_current_time();

  // Server app context
  server_app_ctx_t *server_ctx = new server_app_ctx_t();
  server_ctx->last_path_id = 0;

  // Create a quic context
  picoquic_quic_t *quic = picoquic_create(10, server_cert, server_key, NULL, default_alpn, sample_server_callback, server_ctx,
                                          NULL, NULL, NULL, current_time, NULL,
                                          NULL, NULL, 0);

  if (quic == NULL)
  {
    fprintf(stderr, "Could not create quic context\n");
    return -1;
  }

  // Set some configurations
  picoquic_set_default_congestion_algorithm(quic, picoquic_cubic_algorithm);
  picoquic_set_default_multipath_option(quic, 1);  // Enable multipath
  picoquic_enable_path_callbacks_default(quic, 1); // Enable path callbacks
  // picoquic_set_key_log_file_from_env(quic);
  // picoquic_set_qlog(quic, qlog_dir);
  // picoquic_set_log_level(quic, 1);

  // Keep on waiting for packets
  if (ret == 0)
  {
    ret = picoquic_packet_loop(quic, server_port, 0, 0, 0, 0, NULL, NULL);
  }

  /* And finish. */
  printf("Server exit, ret = %d\n", ret);

  /* Clean up */
  if (quic != NULL)
  {
    picoquic_free(quic);
  }

  return ret;
}

int sample_server_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *stream_ctx)
{

  st_server_app_ctx_t *server_ctx = (st_server_app_ctx_t *)callback_ctx;

  switch (fin_or_event)
  {
  case picoquic_callback_stream_data: // Data received from peer on stream N
  {
    std::string data = std::string((char *)bytes, length);

    // Send a response
    long num_bytes = strtol(data.c_str(), NULL, 10);
    std::cout << "Requested size is " << num_bytes << std::endl
              << std::endl
              << std::endl;

    // picoquic_set_stream_path_affinity(cnx, stream_id, cnx->path[server_ctx->last_path_id]->unique_path_id);
    // picoquic_set_stream_path_affinity(cnx, stream_id, cnx->path[1]->unique_path_id);
    stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    picoquic_set_stream_priority(cnx, stream_id, 0);
    std::cout << "First_stream_id: " << stream_id << std::endl;
    picoquic_add_to_stream(cnx, stream_id, (uint8_t *)msg.c_str(), num_bytes, 0);

    stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    picoquic_set_stream_priority(cnx, stream_id, 1);
    std::cout << "Second_stream_id: " << stream_id << std::endl;
    picoquic_add_to_stream(cnx, stream_id, (uint8_t *)msg.c_str(), num_bytes, 0);

    if (server_ctx->last_path_id == 0)
    {
      server_ctx->last_path_id = 1;
    }
    else
    {
      server_ctx->last_path_id = 0;
    }

    std::cout << "Server callback: response sent" << std::endl;
  }
  break;
  case picoquic_callback_stream_fin: // Fin received from peer on stream N; data is optional
    std::cout << "Server callback: stream fin. length is " << length << std::endl;
    break;
  case picoquic_callback_path_available:
    std::cout << "Client callback: path available" << std::endl;
    break;
  case picoquic_callback_path_suspended:
    std::cout << "Client callback: path suspended" << std::endl;
    break;
  case picoquic_callback_path_deleted:
    std::cout << "Client callback: path deleted" << std::endl;
    break;
  case picoquic_callback_path_quality_changed:
    std::cout << "Client callback: path quality changed" << std::endl;
    break;
  case picoquic_callback_close:
    std::cout << "Server callback: connection closed" << std::endl;
    for (int i = 0; i < cnx->nb_paths; i++)
    {
      std::cout << "Path " << i << " is " << cnx->path[i]->selected << std::endl;
    }
    break;
  default:
    std::cout << "Server callback: unknown event " << fin_or_event << std::endl;
    break;
  }

  return 0;
}

// int sample_server_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode,
//                           void *callback_ctx, void *callback_arg)
// {
//   st_server_app_ctx_t *server_ctx = (st_server_app_ctx_t *)callback_ctx;
//   std::cout << "Server loop callback" << std::endl;
//   switch (cb_mode)
//   {
//   case picoquic_packet_loop_after_receive:
//     std::cout << "Server loop callback: after receive" << std::endl;
//     break;
//   case picoquic_packet_loop_after_send:
//     std::cout << "Server loop callback: after send" << std::endl;
//     break;
//   default:
//     std::cout << "Server loop callback: unknown event " << cb_mode << std::endl;
//     break;
//   }

//   return 0;
// }

// Notes
// typedef enum {
//     picoquic_callback_stream_data = 0, /* Data received from peer on stream N */
//     picoquic_callback_stream_fin, /* Fin received from peer on stream N; data is optional */
//     picoquic_callback_stream_reset, /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
//     picoquic_callback_stop_sending, /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
//     picoquic_callback_stateless_reset, /* Stateless reset received from peer. Stream=0, bytes=NULL, len=0 */
//     picoquic_callback_close, /* Connection close. Stream=0, bytes=NULL, len=0 */
//     picoquic_callback_application_close, /* Application closed by peer. Stream=0, bytes=NULL, len=0 */
//     picoquic_callback_stream_gap,  /* bytes=NULL, len = length-of-gap or 0 (if unknown) */
//     picoquic_callback_prepare_to_send, /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
//     picoquic_callback_almost_ready, /* Data can be sent, but the connection is not fully established */
//     picoquic_callback_ready, /* Data can be sent and received, connection migration can be initiated */
//     picoquic_callback_datagram, /* Datagram frame has been received */
//     picoquic_callback_version_negotiation, /* version negotiation requested */
//     picoquic_callback_request_alpn_list, /* Provide the list of supported ALPN */
//     picoquic_callback_set_alpn, /* Set ALPN to negotiated value */
//     picoquic_callback_pacing_changed, /* Pacing rate for the connection changed */
//     picoquic_callback_prepare_datagram, /* Prepare the next datagram */
//     picoquic_callback_datagram_acked, /* Ack for packet carrying datagram-frame received from peer */
//     picoquic_callback_datagram_lost, /* Packet carrying datagram-frame probably lost */
//     picoquic_callback_datagram_spurious, /* Packet carrying datagram-frame was not really lost */
//     picoquic_callback_path_available, /* A new path is available, or a suspended path is available again */
//     picoquic_callback_path_suspended, /* An available path is suspended */
//     picoquic_callback_path_deleted, /* An existing path has been deleted */
//     picoquic_callback_path_quality_changed /* Some path quality parameters have changed */
// } picoquic_call_back_event_t;

// int sample_server_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode,
//                           void *callback_ctx, void *callback_arg)
// {
//   std::cout << "Server loop callback" << std::endl;
//   return 0;
// }

// ../picoquic_sample client localhost 4433 ./temp <filename>
// ../picoquic_sample server 4433 ./ca-cert.pem ./server-key.pem ./server_files
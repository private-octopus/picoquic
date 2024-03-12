#include <iostream>
#include <picoquic.h>
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include <netinet/in.h>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <fstream>

typedef struct st_client_app_ctx_t
{
  int total_requests;
  int requests_sent;
  long bytes_requested;
  std::string request_msg;
  long total_bytes_received;
  long current_request_bytes_received;
  // std::vector<std::string> responses;
  // int *time_taken;
  long *start_times;
  long *end_times;
  std::chrono::time_point<std::chrono::system_clock> start_timestamp;
  std::chrono::time_point<std::chrono::system_clock> end_timestamp;
  std::string output_file;
} client_app_ctx_t;

int sample_client_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx);

int main(int argc, char *argv[])
{
  std::cout << "Client started" << std::endl;

  int ret = 0;
  char *server_name = "127.0.0.1";
  int server_port = 12000;
  picoquic_quic_t *quic = NULL;
  picoquic_cnx_t *cnx = NULL;
  char *default_alpn = "my_custom_alpn";
  // char *default_alpn = "application layer protocol";
  uint64_t current_time = picoquic_current_time();

  // Create a quic context
  quic = picoquic_create(1, NULL, NULL, NULL, default_alpn, NULL, NULL,
                         NULL, NULL, NULL, current_time, NULL,
                         NULL, NULL, 0); // callback can be specified here too

  if (quic == NULL)
  {
    fprintf(stderr, "Could not create quic context\n");
    ret = -1;
  }

  // // Set some configurations
  picoquic_set_default_congestion_algorithm(quic, picoquic_cubic_algorithm);
  // // picoquic_set_key_log_file_from_env(quic);
  // // picoquic_set_qlog(quic, qlog_dir);
  // // picoquic_set_log_level(quic, 1);

  // Set the server address
  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(server_port);            // Replace with the server port
  server_address.sin_addr.s_addr = inet_addr(server_name); // Replace with the server IP address

  // Create a connection
  cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                            (struct sockaddr *)&server_address, current_time, 0, NULL, default_alpn, 1);

  if (cnx == NULL)
  {
    fprintf(stderr, "Could not create connection context\n");
  }

  // Creating the client context
  // char* message = argv[1];
  // char message[] = "10000";

  client_app_ctx_t *client_ctx = new client_app_ctx_t();
  client_ctx->total_requests = atoi(argv[1]);
  // std::cout << "Total requests: " << client_ctx->total_requests << std::endl;
  client_ctx->requests_sent = 0;
  client_ctx->bytes_requested = strtol(argv[2], NULL, 10);
  // std::cout << "Bytes requested: " << client_ctx->bytes_requested << std::endl;
  client_ctx->request_msg = std::string(argv[2]);
  client_ctx->total_bytes_received = 0;
  client_ctx->current_request_bytes_received = 0;
  // client_ctx->time_taken = new int[client_ctx->total_requests];
  client_ctx->start_times = new long[client_ctx->total_requests];
  client_ctx->end_times = new long[client_ctx->total_requests];
  client_ctx->output_file = std::string(argv[3]);

  // printf("Starting connection to %s, port %d\n", server_name, server_port);

  picoquic_set_callback(cnx, sample_client_callback, client_ctx);
  ret = picoquic_start_client_cnx(cnx);

  if (ret < 0)
  {
    fprintf(stderr, "Could not start connection\n");
    ret = -1;
  }
  else
  {
    /* Printing out the initial CID, which is used to identify log files */
    picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
    // printf("Initial connection ID: ");
    // for (uint8_t i = 0; i < icid.id_len; i++)
    // {
    //   printf("%02x", icid.id[i]);
    // }
    // printf("\n");
  }

  /* Obtain the next available stream ID in the local category */
  // int is_unidir = 0;
  // uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, is_unidir);

  // // Timestamp
  // client_ctx->start_timestamp = std::chrono::high_resolution_clock::now();

  // //  some data
  // ret = picoquic_add_to_stream(cnx, stream_id, (const uint8_t *)client_ctx->request_msg.c_str(), client_ctx->request_msg.length(), 0);
  // client_ctx->requests_sent++;

  // if (ret < 0)
  // {
  //   fprintf(stderr, "Could not send data\n");
  // }

  /* Wait for packets */
  ret = picoquic_packet_loop(quic, 0, server_address.sin_family, 0, 0, 0, NULL, NULL);

  /* Free the Client context */
  // sample_client_free_context(&client_ctx);

  return ret;
}

int sample_client_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx)
{
  client_app_ctx_t *client_ctx = (client_app_ctx_t *)callback_ctx;

  switch (fin_or_event)
  {
  case picoquic_callback_stream_data: // Data received from peer on stream N
    // std::cout << "Client callback: stream data. length is " << length << std::endl;
    // std::cout << "Data: " << std::string((char *)bytes, length) << std::endl;

    // Store the response and if it's the end, send another request
    if (client_ctx->current_request_bytes_received == 0)
    {
      // client_ctx->responses.push_back(std::string((char *)bytes, length));
      client_ctx->current_request_bytes_received += length;
      client_ctx->total_bytes_received += length;
    }
    else
    {
      // client_ctx->responses.back() += std::string((char *)bytes, length);
      client_ctx->current_request_bytes_received += length;
      client_ctx->total_bytes_received += length;
    }

    if (client_ctx->current_request_bytes_received == client_ctx->bytes_requested)
    {
      client_ctx->end_timestamp = std::chrono::high_resolution_clock::now();
      // client_ctx->time_taken[client_ctx->requests_sent - 1] = std::chrono::duration_cast<std::chrono::microseconds>(client_ctx->end_timestamp - client_ctx->start_timestamp).count();
      client_ctx->start_times[client_ctx->requests_sent - 1] = client_ctx->start_timestamp.time_since_epoch().count();
      client_ctx->end_times[client_ctx->requests_sent - 1] = client_ctx->end_timestamp.time_since_epoch().count();
      // std::cout << "Received " << client_ctx->current_request_bytes_received << " bytes" << std::endl
      //           << "Request " << client_ctx->requests_sent << " completed" << std::endl
      //           << "Took " << client_ctx->time_taken[client_ctx->requests_sent - 1] << " microseconds" << std::endl;
      client_ctx->current_request_bytes_received = 0;

      if (client_ctx->requests_sent < client_ctx->total_requests)
      {
        // std::cout << "Sending another request" << std::endl;
        client_ctx->start_timestamp = std::chrono::high_resolution_clock::now();
        picoquic_add_to_stream(cnx, stream_id, (const uint8_t *)client_ctx->request_msg.c_str(), client_ctx->request_msg.length(), 0);
        client_ctx->requests_sent++;
      }
      else
      {
        // std::cout << "All requests sent" << std::endl;
        // for (auto &response : client_ctx->responses)
        // {
        //   std::cout << "Response: " << response.length() << std::endl;
        // }

        // Write to file
        std::ofstream file(client_ctx->output_file);
        if (file.is_open())
        {
          file << "request_send_timestamp, response_receive_timestamp" << std::endl;
        }

        for (int i = 0; i < client_ctx->total_requests; i++)
        {
          file << client_ctx->start_times[i] << "," << client_ctx->end_times[i] << std::endl;
          // std::cout << client_ctx->time_taken[i] << " microseconds" << std::endl;
        }
        file.close();

        // delete[] client_ctx->time_taken;
        delete[] client_ctx->start_times;
        delete[] client_ctx->end_times;
        delete client_ctx;
        exit(0);
      }
    }

    break;
  case picoquic_callback_stream_fin: // Fin received from peer on stream N; data is optional
    // std::cout << "Client callback: stream fin. length is " << length << std::endl;
    break;
  case picoquic_callback_ready:
  {
    // std::cout << "Client callback: ready length " << length << std::endl;
    int is_unidir = 0;
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, is_unidir);
    // std::cout << "Steam id:" << stream_id << std::endl;

    // Timestamp
    client_ctx->start_timestamp = std::chrono::high_resolution_clock::now();

    // Send some data
    picoquic_add_to_stream(cnx, stream_id, (const uint8_t *)client_ctx->request_msg.c_str(), client_ctx->request_msg.length(), 0);
    client_ctx->requests_sent++;

    break;
  }
  default:
    // std::cout << "Client callback: unknown event " << fin_or_event << std::endl;
    break;
  }
  return 0;
}

// two different callback context -> stream or application context

// Can do hostname resolution using picoquic_get_server_address() api

// char message[] = "Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!Hello, server!1234567890!";

// ../picoquic_sample client localhost 4433 ./temp <filename>
// ../picoquic_sample server 4433 ./ca-cert.pem ./server-key.pem ./server_files

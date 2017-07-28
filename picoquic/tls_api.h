#ifndef TLS_API_H
#define TLS_API_H
#include "picoquic.h"

int picoquic_master_tlscontext(picoquic_quic * quic, char * cert_file_name, char * key_file_name);

int picoquic_tlscontext_create(picoquic_quic * quic, picoquic_cnx * cnx);

void picoquic_tlscontext_free(void * ctx);

int picoquic_tlsinput_stream_zero(picoquic_cnx * cnx);

int picoquic_initialize_stream_zero(picoquic_cnx * cnx);

void picoquic_crypto_random(picoquic_quic * quic, void * buf, size_t len);

int picoquic_setup_1RTT_aead_contexts(picoquic_cnx * cnx, int is_server);

size_t picoquic_aead_decrypt(picoquic_cnx *cnx, uint8_t * output, uint8_t * input, size_t input_length,
    uint64_t seq_num, uint8_t * auth_data, size_t auth_data_length);

size_t picoquic_aead_encrypt(picoquic_cnx *cnx, uint8_t * output, uint8_t * input, size_t input_length,
    uint64_t seq_num, uint8_t * auth_data, size_t auth_data_length);

void picoquic_aead_free(void* aead_context);

#endif /* TLS_API_H */

#ifndef TLS_API_H
#define TLS_API_H
#include "picoquic.h"

int picoquic_master_tlscontext(picoquic_quic * quic, char * cert_file_name, char * key_file_name);

int picoquic_tlscontext_create(picoquic_quic * quic, picoquic_cnx * cnx);

void picoquic_tlscontext_free(void * ctx);

int picoquic_tlsinput_stream_zero(picoquic_cnx * cnx);

int picoquic_initialize_stream_zero(picoquic_cnx * cnx);

int picoquic_crypto_random(picoquic_quic * quic, void * buf, size_t len);



#endif /* TLS_API_H */

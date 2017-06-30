#ifndef PICOTLSAPI_H
#define PICOTLSAPI_H


#ifndef picotls_h
/*
 * define here the picotls struct used for storing output
 */
typedef struct st_ptls_buffer_t {
    uint8_t *base;
    size_t capacity;
    size_t off;
    int is_allocated;
} ptls_buffer_t;
#endif

typedef struct _picotlsapi
{
    void* (*get_session_context)(void *);
    int(*process_handshake)(void*, ptls_buffer_t *, const void *, size_t *, void *);
    int(*get_1rtt_key)(void*, const void *, size_t *);
    int(*get_0rtt_key)(void*,const void *, size_t *);
    int(*get_resume_ticket)(void*, const void *, size_t *);
    int(*set_resume_ticket)(void*, const void *, size_t *);
} picotlsapi;

#endif /* PICOTLSAPI_H */

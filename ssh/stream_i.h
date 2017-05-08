/* stream_i.h */

#ifndef STREAM_I_H_FILE
#define STREAM_I_H_FILE

#include "common/buffer.h"
#include "ssh/cipher_i.h"
#include "ssh/mac_i.h"

#include <stdint.h>

enum SSH_STREAM_TYPE {
  SSH_STREAM_TYPE_READ,
  SSH_STREAM_TYPE_WRITE
};

struct SSH_STREAM_WRITE_DATA {
  struct SSH_BUFFER buf_enc;
};

struct SSH_STREAM_READ_DATA {
  struct SSH_BUFFER buf;
  struct SSH_BUFFER buf_enc;
};

struct SSH_STREAM {
  uint32_t seq_num;
  struct SSH_BUFFER pack;

  enum SSH_STREAM_TYPE type;
  union {
    struct SSH_STREAM_WRITE_DATA write;
    struct SSH_STREAM_READ_DATA read;
  } net;
  
  enum SSH_CIPHER_TYPE cipher_type;
  struct SSH_CIPHER_CTX *cipher_ctx;
  uint32_t cipher_block_len;

  enum SSH_MAC_TYPE mac_type;
  struct SSH_MAC_CTX *mac_ctx;
  uint32_t mac_len;
};

void ssh_stream_init(struct SSH_STREAM *stream, enum SSH_STREAM_TYPE type);
void ssh_stream_close(struct SSH_STREAM *stream);

int ssh_stream_set_cipher(struct SSH_STREAM *stream, enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, struct SSH_STRING *iv, struct SSH_STRING *key);
int ssh_stream_set_mac(struct SSH_STREAM *stream, enum SSH_MAC_TYPE type, struct SSH_STRING *key);

struct SSH_BUFFER *ssh_stream_new_packet(struct SSH_STREAM *stream);
int ssh_stream_send_packet(struct SSH_STREAM *stream, int sock);
int ssh_stream_send_is_pending(struct SSH_STREAM *stream);
int ssh_stream_send_flush(struct SSH_STREAM *stream, int sock);

int ssh_stream_recv_packet(struct SSH_STREAM *stream, int sock);

#endif /* STREAM_I_H_FILE */

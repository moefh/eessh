/* stream.h */

#ifndef STREAM_H_FILE
#define STREAM_H_FILE

#include "common/buffer.h"
#include "ssh/cipher.h"
#include "ssh/mac.h"

#include <stdint.h>

struct SSH_STREAM {
  uint32_t seq_num;
  struct SSH_BUFFER pack;
  struct SSH_BUF_READER pack_read;
  struct SSH_BUFFER pack_enc;
  
  enum SSH_CIPHER_TYPE cipher_type;
  struct SSH_CIPHER_CTX *cipher_ctx;
  uint32_t cipher_block_len;

  enum SSH_MAC_TYPE mac_type;
  struct SSH_MAC_CTX *mac_ctx;
  uint32_t mac_len;
};

void ssh_stream_init(struct SSH_STREAM *stream);
void ssh_stream_close(struct SSH_STREAM *stream);

int ssh_stream_set_cipher(struct SSH_STREAM *stream, enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, struct SSH_STRING *iv, struct SSH_STRING *key);
int ssh_stream_set_mac(struct SSH_STREAM *stream, enum SSH_MAC_TYPE type, struct SSH_STRING *key);

int ssh_stream_send_packet(struct SSH_STREAM *stream, int sock);
int ssh_stream_recv_packet(struct SSH_STREAM *stream, int sock);

struct SSH_BUFFER *ssh_stream_new_packet(struct SSH_STREAM *stream);

#endif /* STREAM_H_FILE */

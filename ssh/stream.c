/* stream.c */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ssh/stream_i.h"

#include "common/network_i.h"
#include "ssh/hash_i.h"

#include "common/error.h"
#include "common/debug.h"
#include "crypto/random.h"
#include "ssh/debug.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#define MAX_PACKET_LEN (128*1024)

void ssh_stream_init(struct SSH_STREAM *stream, enum SSH_STREAM_TYPE type)
{
  stream->seq_num = 0;
  stream->pack = ssh_buf_new();

  stream->type = type;
  switch (type) {
  case SSH_STREAM_TYPE_WRITE:
    stream->net.write.pack_enc = ssh_buf_new();
    break;

  case SSH_STREAM_TYPE_READ:
    stream->net.read.buf = ssh_buf_new();
    stream->net.read.buf_enc = ssh_buf_new();
    break;
  }

  stream->cipher_type = SSH_CIPHER_NONE;
  stream->cipher_block_len = 0;
  stream->cipher_ctx = NULL;

  stream->mac_type = SSH_MAC_NONE;
  stream->mac_len = 0;
  stream->mac_ctx = NULL;
}

void ssh_stream_close(struct SSH_STREAM *stream)
{
  if (stream->cipher_ctx != NULL)
    ssh_cipher_free(stream->cipher_ctx);
  if (stream->mac_ctx != NULL)
    ssh_mac_free(stream->mac_ctx);

  ssh_buf_free(&stream->pack);
  switch (stream->type) {
  case SSH_STREAM_TYPE_WRITE:
    ssh_buf_free(&stream->net.write.pack_enc);
    break;
    
  case SSH_STREAM_TYPE_READ:
    ssh_buf_free(&stream->net.read.buf);
    ssh_buf_free(&stream->net.read.buf_enc);
    break;
  }
}

int ssh_stream_set_cipher(struct SSH_STREAM *stream, enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, struct SSH_STRING *iv, struct SSH_STRING *key)
{
  int cipher_block_len;
  
  cipher_block_len = ssh_cipher_get_block_len(type);
  if (cipher_block_len < 0)
    return -1;
  
  if (stream->cipher_ctx != NULL)
    ssh_cipher_free(stream->cipher_ctx);
  if ((stream->cipher_ctx = ssh_cipher_new(type, dir, iv, key)) == NULL)
    return -1;
 
  stream->cipher_type = type;
  stream->cipher_block_len = cipher_block_len;
  ssh_str_free(iv);
  ssh_str_free(key);
  return 0;
}

int ssh_stream_set_mac(struct SSH_STREAM *stream, enum SSH_MAC_TYPE type, struct SSH_STRING *key)
{
  int mac_len;
  
  mac_len = ssh_mac_get_len(type);
  if (mac_len < 0)
    return -1;

  if (stream->mac_ctx != NULL)
    ssh_mac_free(stream->mac_ctx);
  if ((stream->mac_ctx = ssh_mac_new(type, key)) == NULL)
    return -1;
  
  stream->mac_type = type;
  stream->mac_len = mac_len;
  ssh_str_free(key);
  return 0;
}

static uint8_t calc_pad_len(uint32_t pack_len_before_padding, uint8_t block_size)
{
  uint8_t pad_len;

  if (block_size < 8)
    block_size = 8;
  
  pad_len = block_size - pack_len_before_padding % block_size;
  if (pad_len < 4)
    pad_len += block_size;

  return pad_len;
}

/*
 * ==================================================================
 * write
 * ==================================================================
 */

struct SSH_BUFFER *ssh_stream_new_packet(struct SSH_STREAM *stream)
{
  ssh_buf_clear(&stream->pack);
  
  if (ssh_buf_write_u32(&stream->pack, 0) < 0     // pack_len
      || ssh_buf_write_u8(&stream->pack, 0) < 0)  // pad_len
    return NULL;
  return &stream->pack;
}

static int finish_packet(struct SSH_STREAM *stream)
{
  uint8_t pad_len;
  uint8_t *p;

  // write padding
  pad_len = calc_pad_len(stream->pack.len, stream->cipher_block_len);
  if ((p = ssh_buf_get_write_pointer(&stream->pack, pad_len)) == NULL)
    return -1;
  if (stream->cipher_type == SSH_CIPHER_NONE)
    memset(p, 0xff, pad_len);
  else
    crypto_random_gen(p, pad_len);

  ssh_buf_set_u32(stream->pack.data, stream->pack.len-4);
  stream->pack.data[4] = pad_len;

  if (stream->cipher_type != SSH_CIPHER_NONE) {
    ssh_buf_clear(&stream->net.write.pack_enc);
    if ((p = ssh_buf_get_write_pointer(&stream->net.write.pack_enc, stream->pack.len)) == NULL)
      return -1;
    if (ssh_cipher_crypt(stream->cipher_ctx, p, stream->pack.data, stream->pack.len) < 0)
      return -1;
  }

  // write mac past end of packet
  if (stream->mac_type != SSH_MAC_NONE) {
    struct SSH_BUFFER *write_pack = (stream->cipher_type == SSH_CIPHER_NONE) ? &stream->pack : &stream->net.write.pack_enc;
    if (ssh_buf_grow(write_pack, stream->mac_len) < 0)  // only grow buffer, don't change its nominal length
      return -1;

    // calculate MAC
    if (ssh_mac_compute(stream->mac_ctx, write_pack->data + write_pack->len, stream->seq_num, stream->pack.data, stream->pack.len) < 0)
      return -1;
  }

  return 0;
}

int ssh_stream_send_packet(struct SSH_STREAM *stream, int sock)
{
  struct SSH_BUFFER *write_pack = (stream->cipher_type == SSH_CIPHER_NONE) ? &stream->pack : &stream->net.write.pack_enc;

  if (finish_packet(stream) < 0)
    return -1;
  stream->seq_num++;

  if (ssh_net_write_all(sock, write_pack->data, write_pack->len + stream->mac_len) < 0)
    return -1;
  return 0;
}

/*
 * ==================================================================
 * read
 * ==================================================================
 */

static int verify_read_packet(struct SSH_STREAM *stream)
{
  uint8_t block_len;

  // check padding
  if (stream->pack.data[4] < 4 || stream->pack.data[4] > stream->pack.len-5) {
    ssh_set_error("bad padding length: packet_length=%d, pad_length=%d", (int) stream->pack.len-4, stream->pack.data[4]);
    return -1;
  }
  block_len = (stream->cipher_block_len != 0) ? stream->cipher_block_len : 8;
  if (stream->pack.len % block_len != 0) {
    ssh_set_error("bad padding len in received packet: %d mod %d = %d",
                  (int) stream->pack.len, block_len, (int) (stream->pack.len % block_len));
    return -1;
  }

  // check mac
  if (stream->mac_type != SSH_MAC_NONE) {
    uint8_t digest[SSH_HASH_MAX_LEN];

    // verify MAC
    if (ssh_mac_compute(stream->mac_ctx, digest, stream->seq_num, stream->pack.data, stream->pack.len) < 0)
      return -1;
    if (memcmp(digest, stream->pack.data + stream->pack.len, stream->mac_len) != 0) {  // [TODO: prevent timing attack]
      ssh_log("input packet has bad MAC:\n");
      dump_mem("received MAC", stream->pack.data + stream->pack.len, stream->mac_len);
      dump_mem("computed MAC", digest, stream->mac_len);
      ssh_set_error("bad mac in incoming packet");
      return -1;
    }
  }
  
  return 0;
}

/*
 * Read data from network (decrypting if necessary) until there are
 * 'len' bytes of unencrypted data available.
 */
static int stream_recv_fill_buffer(struct SSH_STREAM *stream, int sock, size_t ciphertext_len, size_t plaintext_len)
{
  size_t total_len;
  size_t read_len;
  struct SSH_BUFFER *read_buf;

  total_len = ciphertext_len + plaintext_len;
  
  if (stream->cipher_type != SSH_CIPHER_NONE) {
    read_buf = &stream->net.read.buf_enc;
    if (total_len < stream->net.read.buf.len + read_buf->len)
      read_len = 0;
    else
      read_len = total_len - stream->net.read.buf.len - read_buf->len;
  } else {
    read_buf = &stream->net.read.buf;
    if (total_len < read_buf->len)
      read_len = 0;
    else
      read_len = total_len - read_buf->len;
  }

  // read from network to fill 'read_buf' up to 'len' bytes
  if (read_len > 0) {
    ssize_t r;

    // can't use ssh_buf_get_write_pointer() here because it's OK for the read to fail with EWOULDBLOCK
    if (ssh_buf_grow(read_buf, read_len) < 0) {
      errno = 0;
      return -1;
    }
    if ((r = ssh_net_read(sock, read_buf->data + read_buf->len, read_len)) < 0)
      return -1;
    read_buf->len += r;
  }

  // decrypt data if cipher is set
  if (stream->cipher_type != SSH_CIPHER_NONE && total_len > stream->net.read.buf.len) {
    uint8_t *p;
    size_t consume_len = total_len - stream->net.read.buf.len;

    if (plaintext_len < consume_len) {
      size_t dec_len = consume_len - plaintext_len;
      
      if ((p = ssh_buf_get_write_pointer(&stream->net.read.buf, dec_len)) == NULL
          || ssh_cipher_crypt(stream->cipher_ctx, p, read_buf->data, dec_len) < 0) {
        errno = 0;
        return -1;
      }
    }
    
    if (consume_len > 0) {
      size_t copy_len = MIN(consume_len, plaintext_len);

      if ((p = ssh_buf_get_write_pointer(&stream->net.read.buf, copy_len)) == NULL) {
        errno = 0;
        return -1;
      }
      memcpy(p, read_buf->data + consume_len - copy_len, copy_len);
    }
    if (ssh_buf_remove_data(read_buf, 0, consume_len) < 0) {
      errno = 0;
      return -1;
    }
  }
  
  return 0;
}

int ssh_stream_recv_packet(struct SSH_STREAM *stream, int sock)
{
  uint32_t pack_len;
  size_t min_len, pack_data_len;

  // ensure we have enough to read the packet len
  min_len = (stream->cipher_type == SSH_CIPHER_NONE) ? 4 : stream->cipher_block_len;
  if (stream->net.read.buf.len < min_len
      && stream_recv_fill_buffer(stream, sock, min_len, 0) < 0)
    return -1;

  // get packet len
  pack_len = ssh_buf_get_u32(stream->net.read.buf.data);
  if (pack_len < 12 || pack_len > MAX_PACKET_LEN) {
    ssh_set_error("invalid packet size (%u=0x%x)", pack_len, pack_len);
    errno = 0;
    return -1;
  }

  // read rest of the packet
  pack_data_len = pack_len + 4;
  if (stream_recv_fill_buffer(stream, sock, pack_data_len, stream->mac_len) < 0)
    return -1;

  // return the packet
  ssh_buf_clear(&stream->pack);
  if (ssh_buf_append_data(&stream->pack, stream->net.read.buf.data, pack_data_len) < 0
      || ssh_buf_grow(&stream->pack, stream->mac_len) < 0) {
    errno = 0;
    return -1;
  }
  memcpy(stream->pack.data + stream->pack.len, stream->net.read.buf.data + pack_data_len, stream->mac_len);
  if (ssh_buf_remove_data(&stream->net.read.buf, 0, pack_data_len + stream->mac_len) < 0) {
    errno = 0;
    return -1;
  }
  
  if (verify_read_packet(stream) < 0) {
    errno = 0;
    return -1;
  }
  
  stream->seq_num++;
  return 0;
}

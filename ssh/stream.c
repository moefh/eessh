/* stream.c */

#include <stdlib.h>
#include <string.h>

#include "ssh/stream.h"

#include "common/error.h"
#include "common/debug.h"
#include "common/network.h"
#include "crypto/random.h"
#include "ssh/hash.h"
#include "ssh/debug.h"

void ssh_stream_init(struct SSH_STREAM *stream)
{
  stream->seq_num = 0;
  stream->pack = ssh_buf_new();
  stream->pack_enc = ssh_buf_new();

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
  ssh_buf_free(&stream->pack_enc);
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
  enum SSH_MAC_MODE mac_mode;

  //  dump_mem("stream
  
  mac_len = ssh_mac_get_len(type);
  if (mac_len < 0)
    return -1;
  mac_mode = ssh_mac_get_mode(type);
  if (mac_mode == SSH_MAC_INVALID_MODE)
    return -1;

  if (stream->mac_ctx != NULL)
    ssh_mac_free(stream->mac_ctx);
  if ((stream->mac_ctx = ssh_mac_new(type, key)) == NULL)
    return -1;
  
  stream->mac_type = type;
  stream->mac_mode = mac_mode;
  stream->mac_len = mac_len;
  ssh_str_free(key);
  return 0;
}

struct SSH_BUFFER *ssh_stream_new_packet(struct SSH_STREAM *stream)
{
  ssh_buf_clear(&stream->pack);
  
  if (ssh_buf_write_u32(&stream->pack, 0) < 0     // pack_len
      || ssh_buf_write_u8(&stream->pack, 0) < 0)  // pad_len
    return NULL;
  return &stream->pack;
}

static uint8_t calc_pad_len(uint32_t pack_len_before_padding, uint8_t block_size)
{
  uint8_t pad_len;

  //ssh_log("calculating padding len: pack_len_before_padding=%u, block_size=%u\n", pack_len_before_padding, block_size);

  if (block_size < 8)
    block_size = 8;
  
  pad_len = block_size - pack_len_before_padding % block_size;
  if (pad_len < 4)
    pad_len += block_size;

  return pad_len;
}

/*
 * Prepare packet to write to the network
 */
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
    ssh_buf_clear(&stream->pack_enc);
    if ((p = ssh_buf_get_write_pointer(&stream->pack_enc, stream->pack.len)) == NULL)
      return -1;
    if (ssh_cipher_crypt(stream->cipher_ctx, p, stream->pack.data, stream->pack.len) < 0)
      return -1;
  }

  // write mac past end of packet
  if (stream->mac_type != SSH_MAC_NONE) {
    struct SSH_BUFFER *read_pack = (stream->mac_mode == SSH_MAC_MAC_THEN_ENCRYPT) ? &stream->pack : &stream->pack_enc;
    struct SSH_BUFFER *write_pack = (stream->cipher_type == SSH_CIPHER_NONE) ? &stream->pack : &stream->pack_enc;
    if (ssh_buf_grow(write_pack, stream->mac_len) < 0)  // only grow buffer, don't change its nominal length
      return -1;

    // calculate MAC
    //memset(write_pack->data + write_pack->len, 0, stream->mac_len);
    if (ssh_mac_compute(stream->mac_ctx, write_pack->data + write_pack->len, stream->seq_num, read_pack->data, read_pack->len) < 0)
      return -1;
  }

  return 0;
}

/*
 * Write packet to network
 */
int ssh_stream_send_packet(struct SSH_STREAM *stream, int sock)
{
  struct SSH_BUFFER *write_pack = (stream->cipher_type == SSH_CIPHER_NONE) ? &stream->pack : &stream->pack_enc;

  //ssh_log("### send start ############################################################################\n");
  
  if (finish_packet(stream) < 0)
    return -1;
  stream->seq_num++;

  //dump_packet("sending packet", &stream->pack, 0);
  //dump_mem("sending packet", write_pack->data, write_pack->len + stream->mac_len);
 
  if (ssh_net_write_all(sock, write_pack->data, write_pack->len + stream->mac_len) < 0)
    return -1;
  return 0;
}

/*
 * Verify packet just read from network
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
    ssh_set_error("bad padding len in received packet of size %d: %d", (int) stream->pack.len-4, stream->pack.data[4]);
    return -1;
  }

  // check mac
  if (stream->mac_type != SSH_MAC_NONE) {
    uint8_t digest[SSH_HASH_MAX_LEN];
    struct SSH_BUFFER *read_pack = (stream->mac_mode == SSH_MAC_MAC_THEN_ENCRYPT) ? &stream->pack : &stream->pack_enc;

#if 0
    if (stream->mac_mode == SSH_MAC_MAC_THEN_ENCRYPT) {
      ssh_log("**** MACing plaintext packet\n");
      dump_mem("plaintext to dump", read_pack->data, read_pack->len);
    } else {
      ssh_log("**** MACing ciphertext packet\n");
    }
#endif
    
    // verify MAC
    memset(digest, 0xff, sizeof(digest));
    if (ssh_mac_compute(stream->mac_ctx, digest, stream->seq_num, read_pack->data, read_pack->len) < 0)
      return -1;
    if (memcmp(digest, read_pack->data + read_pack->len, stream->mac_len) != 0) {  // [TODO: prevent timing attack]
      ssh_log("input packet has bad MAC:\n");
      dump_mem("received MAC", read_pack->data + read_pack->len, stream->mac_len);
      dump_mem("computed MAC", digest, stream->mac_len);
      ssh_set_error("bad mac in incoming packet");
      return -1;
    }
  }
  
  return 0;
}

/*
 * Read packet from network
 */
int ssh_stream_recv_packet(struct SSH_STREAM *stream, int sock)
{
  struct SSH_BUFFER *read_pack;
  uint32_t first_block_len, remainder_len, pack_len;
  uint8_t *p;

  //ssh_log("### recv start ############################################################################\n");
  
  read_pack = (stream->cipher_type == SSH_CIPHER_NONE) ? &stream->pack : &stream->pack_enc;

  // read first block to discover the packet length
  first_block_len = (stream->cipher_block_len == 0) ? 8 : stream->cipher_block_len;
  //ssh_log("######## first_block_len: %d (cipher type: %d)\n", first_block_len, stream->cipher_type);
  ssh_buf_clear(read_pack);
  if ((p = ssh_buf_get_write_pointer(read_pack, first_block_len)) == NULL)
    return -1;
  if (ssh_net_read_all(sock, p, first_block_len) < 0)
    return -1;
  //dump_mem("######## first block (before decryption)", read_pack->data, read_pack->len);

  // decrypt first block
  if (stream->cipher_type != SSH_CIPHER_NONE) {
    //ssh_log("##### DECRYPTING\n");
    ssh_buf_clear(&stream->pack);
    if ((p = ssh_buf_get_write_pointer(&stream->pack, first_block_len)) == NULL)
      return -1;
    if (ssh_cipher_crypt(stream->cipher_ctx, p, read_pack->data, read_pack->len) < 0)
      return -1;
  }

  //dump_mem("######## first block (after decyption)", stream->pack.data, stream->pack.len);
  
  // get packet length
  pack_len = ssh_buf_get_u32(stream->pack.data);
  if (pack_len == 0 || pack_len > 65536) {
    ssh_set_error("invalid packet size (%u=0x%x)", pack_len, pack_len);
    return -1;
  }

  // read rest of the packet
  remainder_len = pack_len + stream->mac_len - first_block_len + 4;
  //ssh_log("######## remainder_len: %d\n", remainder_len);
  if ((p = ssh_buf_get_write_pointer(read_pack, remainder_len)) == NULL)
    return -1;
  if (ssh_net_read_all(sock, p, remainder_len) < 0)
    return -1;
  read_pack->len = pack_len + 4;
  //dump_mem("REMAINDER OF ENCRYPTED PACKET", read_pack->data + first_block_len, remainder_len);
  
  // decrypt rest of the packet (excluding mac)
  if (stream->cipher_type != SSH_CIPHER_NONE) {
    //ssh_log("##### DECRYPTING\n");
    if ((p = ssh_buf_get_write_pointer(&stream->pack, remainder_len - stream->mac_len)) == NULL)
      return -1;
    if (ssh_cipher_crypt(stream->cipher_ctx, p, read_pack->data + first_block_len, remainder_len - stream->mac_len) < 0)
      return -1;
    memcpy(stream->pack.data + pack_len + 4, read_pack->data + pack_len + 4, stream->mac_len);
    stream->pack.len = pack_len + 4;
  }
  
  //dump_mem("######## full packet read", stream->pack.data, stream->pack.len);

  if (verify_read_packet(stream) < 0)
    return -1;
  
  stream->seq_num++;
  stream->pack_read = ssh_buf_reader_new_from_buffer(&stream->pack);
  ssh_buf_read_u32(&stream->pack_read, NULL);  // skip packet length
  ssh_buf_read_u8(&stream->pack_read, NULL);   // skip padding length
  return 0;
}

/* debug.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "ssh/debug.h"

#include "common/error.h"
#include "common/debug.h"
#include "common/buffer.h"
#include "ssh/ssh_constants.h"

#define MAKE_BUFFER_DUMPER(func) \
  void func(const char *label, struct SSH_BUFFER *b, uint32_t mac_len) { \
    struct SSH_BUF_READER r = ssh_buf_reader_new_from_buffer(b);	\
    ssh_buf_read_u32(&r, NULL);						\
    ssh_buf_read_u8(&r, NULL);						\
    func ## _reader(label, &r, mac_len);				\
  }

MAKE_BUFFER_DUMPER(dump_packet)
void dump_packet_reader(const char *label, struct SSH_BUF_READER *buf, uint32_t mac_len)
{
  uint32_t pack_len;
  int payload_len, pad_len;

  pack_len = ssh_buf_get_u32(buf->data);
  pad_len = (buf->len >= 5) ? buf->data[4] : -1;
  payload_len = (int) buf->len - pad_len - 5;

  ssh_log("------------------------------------------------------------------------\n");
  ssh_log("--- %s\n", label);
  if (pack_len != buf->len-4)
    ssh_log("!!!! WARNING: packet len differs from what buffer len contains (%u != %u)\n", pack_len, (unsigned int) buf->len - 4);
  ssh_log("- packet_length     %u\n", (unsigned int) buf->len);
  ssh_log("- padding_length    %d\n", pad_len);
  ssh_log("- message           %s (%u)\n", (payload_len > 0) ? ssh_const_get_msg_name(buf->data[5]) : "--", (payload_len > 0) ? buf->data[5] : 0);
  if (payload_len > 0)
    dump_mem("- payload", buf->data + 5, payload_len);
  if (pad_len > 0)
    dump_mem("- padding", buf->data + 5 + payload_len, pad_len);
  if (mac_len > 0)
    dump_mem("- mac", buf->data + buf->len, mac_len);
  ssh_log("------------------------------------------------------------------------\n");
}

MAKE_BUFFER_DUMPER(dump_kexinit_packet)
void dump_kexinit_packet_reader(const char *label, struct SSH_BUF_READER *pack, uint32_t mac_len)
{
  struct SSH_STRING kex_algos;
  struct SSH_STRING server_host_key_algos;
  struct SSH_STRING encryption_algos_cts;
  struct SSH_STRING encryption_algos_stc;
  struct SSH_STRING mac_algos_cts;
  struct SSH_STRING mac_algos_stc;
  struct SSH_STRING compression_algos_cts;
  struct SSH_STRING compression_algos_stc;
  struct SSH_STRING languages_cts;
  struct SSH_STRING languages_stc;
  uint8_t first_kex_packet_follows;
  uint32_t reserved;

  if (ssh_buf_read_u8(pack, NULL) < 0      // msg_type
      || ssh_buf_read_skip(pack, 16) < 0   // cookie
      || ssh_buf_read_string(pack, &kex_algos) < 0
      || ssh_buf_read_string(pack, &server_host_key_algos) < 0
      || ssh_buf_read_string(pack, &encryption_algos_cts) < 0
      || ssh_buf_read_string(pack, &encryption_algos_stc) < 0
      || ssh_buf_read_string(pack, &mac_algos_cts) < 0
      || ssh_buf_read_string(pack, &mac_algos_stc) < 0
      || ssh_buf_read_string(pack, &compression_algos_cts) < 0
      || ssh_buf_read_string(pack, &compression_algos_stc) < 0
      || ssh_buf_read_string(pack, &languages_cts) < 0
      || ssh_buf_read_string(pack, &languages_stc) < 0
      || ssh_buf_read_u8(pack, &first_kex_packet_follows) < 0
      || ssh_buf_read_u32(pack, &reserved) < 0) {
    ssh_log("ERROR decoding kex packet: %s\n", ssh_get_error());
    return;
  }

  ssh_log("------------------------------------------------------------------------\n");
  ssh_log("--- %s\n", label);
  ssh_log("--- SSH_MSG_KEXINIT packet ---------------------------------------------\n");
  ssh_log("- pad_len:                  %d\n", pack->data[4]);
  dump_mem("cookie", pack->data + 2, 16);
  ssh_log("- kex_algos:                '%.*s'\n", (int) kex_algos.len, kex_algos.str);
  ssh_log("- server_host_key_algos:    '%.*s'\n", (int) server_host_key_algos.len, server_host_key_algos.str);
  ssh_log("- encryption_algos_cts:     '%.*s'\n", (int) encryption_algos_cts.len, encryption_algos_cts.str);
  ssh_log("- encryption_algos_stc:     '%.*s'\n", (int) encryption_algos_stc.len, encryption_algos_stc.str);
  ssh_log("- mac_algos_cts:            '%.*s'\n", (int) mac_algos_cts.len, mac_algos_cts.str);
  ssh_log("- mac_algos_stc:            '%.*s'\n", (int) mac_algos_stc.len, mac_algos_stc.str);
  ssh_log("- compression_algos_cts:    '%.*s'\n", (int) compression_algos_cts.len, compression_algos_cts.str);
  ssh_log("- compression_algos_stc:    '%.*s'\n", (int) compression_algos_stc.len, compression_algos_stc.str);
  ssh_log("- languages_cts:            '%.*s'\n", (int) languages_cts.len, languages_cts.str);
  ssh_log("- languages_stc:            '%.*s'\n", (int) languages_stc.len, languages_stc.str);
  ssh_log("- first_kex_packet_follows: %d\n", first_kex_packet_follows);
  ssh_log("- reserved:                 %d\n", reserved);
  ssh_log("------------------------------------------------------------------------\n");
}

/*
 * Insert a plain-text (no encryption or MAC) packet in the given buffer
 */
int debug_gen_packet(struct SSH_BUFFER *buf, uint8_t type, uint8_t *payload, size_t payload_len)
{
  uint8_t pad_len, i;
  size_t start_len;

  start_len = buf->len;
  
  // data
  if (ssh_buf_write_u32(buf, 0)
      || ssh_buf_write_u8(buf, 0) < 0
      || ssh_buf_write_u8(buf, type) < 0
      || ssh_buf_append_data(buf, payload, payload_len) < 0)
    return -1;

  // padding
  pad_len = 8 - (buf->len-start_len) % 8;
  if (pad_len < 4)
    pad_len += 8;
  for (i = pad_len; i > 0; i--)
    if (ssh_buf_append_data(buf, &i, 1) < 0)
      return -1;

  // fix lengths
  ssh_buf_set_u32(buf->data + start_len, buf->len-start_len - 4);
  buf->data[start_len + 4] = pad_len;

  dump_mem("generated packet", buf->data + start_len, buf->len - start_len);
  
  return 0;
}

int debug_gen_string_packet(struct SSH_BUFFER *buf, uint8_t type, char *str)
{
  uint8_t data[1024];
  size_t str_len;

  str_len = strlen(str);
  if (4 + str_len > sizeof(data)) {
    ssh_set_error("string too large");
    return -1;
  }
  ssh_buf_set_u32(data, str_len);
  memcpy(data + 4, str, str_len);

  return debug_gen_packet(buf, type, data, 4 + str_len);
}

/* debug.h */

#ifndef DEBUG_H_FILE
#define DEBUG_H_FILE

#include <stdint.h>

#include "common/buffer.h"

void dump_packet(const char *label, struct SSH_BUFFER *pack, uint32_t mac_len);
void dump_packet_reader(const char *label, struct SSH_BUF_READER *pack, uint32_t mac_len);

void dump_kexinit_packet(const char *label, struct SSH_BUFFER *pack, uint32_t mac_len);
void dump_kexinit_packet_reader(const char *label, struct SSH_BUF_READER *pack, uint32_t mac_len);

int debug_gen_packet(struct SSH_BUFFER *buf, uint8_t type, uint8_t *payload, size_t payload_len);
int debug_gen_string_packet(struct SSH_BUFFER *buf, uint8_t type, char *str);

#endif /* DEBUG_H_FILE */

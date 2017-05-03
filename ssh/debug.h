/* debug.h */

#ifndef DEBUG_H_FILE
#define DEBUG_H_FILE

#include <stdint.h>

#include "common/buffer.h"

void dump_packet(const char *label, struct SSH_BUFFER *pack, uint32_t mac_len);
void dump_packet_reader(const char *label, struct SSH_BUF_READER *pack, uint32_t mac_len);

void dump_kexinit_packet(const char *label, struct SSH_BUFFER *pack, uint32_t mac_len);
void dump_kexinit_packet_reader(const char *label, struct SSH_BUF_READER *pack, uint32_t mac_len);

#endif /* DEBUG_H_FILE */

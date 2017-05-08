/* debug.h */

#ifndef COMMON_DEBUG_H_FILE
#define COMMON_DEBUG_H_FILE

#include <stdint.h>

#include "common/buffer.h"

#define DEBUG_CONN       0
#define DEBUG_KEX        0
#define DEBUG_USERAUTH   0

void ssh_log(const char *fmt, ...)  __attribute__ ((format (printf, 1, 2)));
void dump_string(const char *label, const struct SSH_STRING *str);
void dump_mem(const char *label, const void *data, size_t len);

#endif /* COMMON_DEBUG_H_FILE */

/* debug.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include "common/debug.h"

void ssh_log(const char *fmt, ...)
{
  va_list ap;
  
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);

  // kludge for when logging in raw mode
  if (strchr(fmt, '\n') != NULL) {
    putchar('\r');
    fflush(stdout);
  }
}

void dump_string(const char *label, const struct SSH_STRING *str)
{
  dump_mem(label, str->str, str->len);
}

void dump_mem(const char *label, const void *data, size_t len)
{
  char str[18];
  size_t cur, str_len;

  if (label == NULL)
    ssh_log("* dumping %u bytes\n", (unsigned int) len);
  else
    ssh_log("%s (%u bytes)\n", label, (unsigned int) len);
  
  cur = 0;
  while (cur < len) {
    const uint8_t *line = (const uint8_t *) data + cur;
    size_t i, si;

    ssh_log("| ");
    str_len = (len - cur > 16) ? 16 : len - cur;
    for (si = i = 0; i < str_len; i++) {
      ssh_log("%02x ", line[i]);
      str[si++] = (line[i] >= 32 && line[i] < 127) ? line[i] : '.';
      if (i == 7) {
        ssh_log(" ");
        str[si++] = ' ';
      }
    }
    str[si++] = '\0';
    cur += str_len;

    for (i = str_len; i < 16; i++) {
      ssh_log("   ");
      if (i == 7)
        ssh_log(" ");
    }
    ssh_log("| %-17s |\n", str);
  }
}

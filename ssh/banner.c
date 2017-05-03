/* banner.c */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ssh/banner.h"

#include "common/error.h"
#include "common/network.h"

static int read_line(int sock, uint8_t *buf, size_t max, size_t *len)
{
  size_t pos = 0;
  
  while (pos < max) {
    ssize_t r = ssh_net_read(sock, buf + pos, 1);
    if (r <= 0) {
      ssh_set_error("read error");
      return -1;
    }
    pos += r;
    if (pos > 0 && buf[pos-1] == '\n') {
      *len = pos;
      return 0;
    }
  }
  *len = pos;
  return 0;
}

int ssh_banner_read(struct SSH_HOST_BANNER *banner, int sock)
{
  int at_line_start;
  uint8_t *end;
  
  // read protocol version
  at_line_start = 1;
  while (1) {
    if (read_line(sock, banner->buf, sizeof(banner->buf), &banner->len) < 0)
      return -1;
    if (banner->buf[banner->len-1] != '\n') {
      // ignore incomplete lines
      at_line_start = 0;
      continue;
    }
    if (! at_line_start) {
      // ignore continuation lines
      at_line_start = 1;
      continue;
    }
    
    if (banner->len >= 5 && memcmp(banner->buf, "SSH-", 4) == 0)
      break;
  }

  end = memchr(banner->buf, '\r', banner->len);
  if (end == NULL)
    end = memchr(banner->buf, '\n', banner->len);
  if (end == NULL)
    end = banner->buf + banner->len;
  banner->len = end - banner->buf;

  banner->version.str = banner->buf + 4;
  banner->software.str = memchr(banner->version.str, '-', banner->buf + banner->len - banner->version.str);
  if (banner->software.str == NULL) {
    ssh_set_error("invalid protocol version string");
    return -1;
  }
  banner->version.len = banner->software.str - banner->version.str;
  banner->software.str++;
  banner->comments.str = memchr(banner->software.str, ' ', banner->buf + banner->len - banner->software.str);
  if (banner->comments.str != NULL) {
    banner->software.len = banner->comments.str - banner->software.str;
    banner->comments.str++;
    banner->comments.len = end - banner->comments.str;
  } else {
    banner->software.len = end - banner->software.str;
    banner->comments.str = banner->software.str + banner->software.len;
    banner->comments.len = 0;
  }

  return 0;
}

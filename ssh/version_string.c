/* version_string.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ssh/version_string_i.h"

#include "common/network_i.h"

#include "common/error.h"
#include "common/debug.h"

#define VERSION_BUF_LEN 512

static int is_version_line(const uint8_t *line, size_t len)
{
  if (len > 4 && memcmp(line, "SSH-", 4) == 0)
    return 1;
  return 0;
}

/*
 * Get version line from (in, in_len).
 *
 * On success, returns:
 *  (*ver, *ver_len)   = version string ((NULL, 0) if more data is needed)
 *  (*rest, *rest_len) = unprocessed part of the buffer
 */
static int get_version_line(const uint8_t *in, size_t in_len, const uint8_t **ver, size_t *ver_len, const uint8_t **rest, size_t *rest_len)
{
  const uint8_t *cur;
  size_t cur_len;

  cur = in;
  cur_len = in_len;
  while (cur_len > 0) {
    const uint8_t *end = memchr(cur, '\n', cur_len);
    if (end == NULL)
      break;
    end++;
    if (is_version_line(cur, end - cur)) {
      *ver = cur;
      *ver_len = end - cur;
      *rest = end;
      *rest_len = (in + in_len) - end;
      return 0;
    }
    cur_len -= end - cur;
    cur = end;
  }
  *ver = NULL;
  *ver_len = 0;
  *rest = cur;
  *rest_len = in + in_len - cur;
  return 0;
}

static int read_line(int sock, struct SSH_VERSION_STRING *ver_str, struct SSH_BUFFER *buf)
{
  ssize_t read_len;
  const uint8_t *ver, *rest;
  size_t ver_len, rest_len;
  
  ssh_buf_clear(buf);
  while (1) {
    if (ssh_buf_grow(buf, VERSION_BUF_LEN) < 0)
      return -1;
    read_len = ssh_net_read(sock, buf->data + buf->len, VERSION_BUF_LEN);
    if (read_len < 0)
      return -1;
    buf->len += read_len;

    if (get_version_line(buf->data, buf->len, &ver, &ver_len, &rest, &rest_len) < 0)
      return -1;

    if (ver != NULL) {
      if (ver_len > SSH_VERSION_STRING_MAX_SIZE) {
        ssh_set_error("version string too large");
        return -1;
      }
      memcpy(ver_str->buf, ver, ver_len);
      ver_str->len = ver_len;
    }

    memmove(buf->data, rest, rest_len);
    buf->len = rest_len;
    
    if (ver != NULL)
      return 0;
  }
}

static int parse_line(struct SSH_VERSION_STRING *ver_str)
{
  uint8_t *end;

  end = ver_str->buf + ver_str->len - 1;
  while (end > ver_str->buf && (*end == '\r' || *end == '\n'))
    end--;
  end++;
  ver_str->len = end - ver_str->buf;

  ver_str->version.str = ver_str->buf + 4;
  ver_str->software.str = memchr(ver_str->version.str, '-', ver_str->buf + ver_str->len - ver_str->version.str);
  if (ver_str->software.str == NULL) {
    ssh_set_error("invalid server protocol version string");
    return -1;
  }
  ver_str->version.len = ver_str->software.str - ver_str->version.str;
  ver_str->software.str++;
  ver_str->comments.str = memchr(ver_str->software.str, ' ', ver_str->buf + ver_str->len - ver_str->software.str);
  if (ver_str->comments.str != NULL) {
    ver_str->software.len = ver_str->comments.str - ver_str->software.str;
    ver_str->comments.str++;
    ver_str->comments.len = end - ver_str->comments.str;
  } else {
    ver_str->software.len = end - ver_str->software.str;
    ver_str->comments.str = ver_str->software.str + ver_str->software.len;
    ver_str->comments.len = 0;
  }

  return 0;
}

/*
 * Read version string from the socket. Any extra data read from the
 * socket is put in 'rest'.
 */
int ssh_version_string_read(struct SSH_VERSION_STRING *ver_str, int sock, struct SSH_BUFFER *rest)
{
  if (read_line(sock, ver_str, rest) < 0
      || parse_line(ver_str) < 0)
    return -1;
  return 0;
}

int ssh_version_string_build(struct SSH_VERSION_STRING *ver_str, const char *software, const char *comments)
{
  int len = snprintf((char *) ver_str->buf, VERSION_BUF_LEN, "SSH-2.0-%s %s\r\n", software, comments);
  if (len < 0 || len >= VERSION_BUF_LEN) {
    ssh_set_error("version string too large");
    return -1;
  }
  ver_str->len = len;
  
  if (parse_line(ver_str) < 0)
    return -1;
  return 0;
}

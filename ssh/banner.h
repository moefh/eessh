/* banner.h */

#ifndef BANNER_H_FILE
#define BANNER_H_FILE

#include <stddef.h>
#include <stdint.h>

#include "common/buffer.h"

#define SSH_VERSION_STRING_MAX_SIZE 512

struct SSH_VERSION_STRING {
  uint8_t buf[SSH_VERSION_STRING_MAX_SIZE];
  size_t len;
  struct SSH_STRING version;
  struct SSH_STRING software;
  struct SSH_STRING comments;
};

int ssh_version_string_read(struct SSH_VERSION_STRING *ver_str, int sock, struct SSH_BUFFER *rest);

#endif /* BANNER_H_FILE */

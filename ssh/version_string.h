/* version_string.h */

#ifndef VERSION_STRING_H_FILE
#define VERSION_STRING_H_FILE

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

#endif /* VERSION_STRING_H_FILE */

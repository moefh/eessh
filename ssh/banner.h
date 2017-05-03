/* banner.h */

#ifndef BANNER_H_FILE
#define BANNER_H_FILE

#include "common/buffer.h"

struct SSH_HOST_BANNER {
  uint8_t buf[255];
  size_t len;
  struct SSH_STRING version;
  struct SSH_STRING software;
  struct SSH_STRING comments;
};

int ssh_banner_read(struct SSH_HOST_BANNER *banner, int sock);

#endif /* BANNER_H_FILE */

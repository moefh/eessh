/* verify.h */

#ifndef VERIFY_H_FILE
#define VERIFY_H_FILE

#include <stdint.h>

#include "common/buffer.h"

enum SSH_VERIFY_TYPE {
  SSH_VERIFY_RSA,

  SSH_VERIFY_INVALID
};

int ssh_verify_check_signature(struct SSH_STRING *key, struct SSH_STRING *signature, struct SSH_STRING *data);

#endif /* VERIFY_H_FILE */

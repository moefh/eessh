/* kex.h */

#ifndef KEX_H_FILE
#define KEX_H_FILE

#include <stdint.h>

#include "connection.h"

enum SSH_KEX_TYPE {
  SSH_KEX_DH_GROUP_1,
  SSH_KEX_DH_GROUP_14,

  SSH_KEX_INVALID
};

struct SSH_KEX;

enum SSH_KEX_TYPE ssh_kex_get_by_name_n(const uint8_t *name, size_t len);
enum SSH_KEX_TYPE ssh_kex_get_by_name(const char *name);

int ssh_kex_run(struct SSH_CONN *conn);

#endif /* KEX_H_FILE */

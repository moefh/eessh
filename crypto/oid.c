/* oid.c */

#include <stdlib.h>
#include <stdint.h>

#include "crypto/oid.h"

#include "common/error.h"

struct OID_DATA {
  unsigned int type;
  const uint8_t *data;
  size_t len;
};

static const uint8_t oid_sha1[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
  0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static const struct OID_DATA hash_oids[] = {
  { SSH_HASH_SHA1, oid_sha1, sizeof(oid_sha1) },
};

int crypto_oid_get_for_hash(enum SSH_HASH_TYPE hash_type, struct SSH_STRING *out)
{
  int i;

  for (i = 0; i < sizeof(hash_oids)/sizeof(hash_oids[0]); i++) {
    if (hash_oids[i].type == hash_type) {
      *out = ssh_str_new((uint8_t *) hash_oids[i].data, hash_oids[i].len);
      return 0;
    }
  }

  ssh_set_error("unknown hash type");
  return -1;
}

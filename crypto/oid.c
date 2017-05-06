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

static const uint8_t oid_sha256[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20,
};

static const uint8_t oid_sha512[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
  0x00, 0x04, 0x40
};

static const struct OID_DATA hash_oids[] = {
  { SSH_HASH_SHA1,     oid_sha1,   sizeof(oid_sha1)   },
  { SSH_HASH_SHA2_256, oid_sha256, sizeof(oid_sha256) },
  { SSH_HASH_SHA2_512, oid_sha512, sizeof(oid_sha512) },
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

  ssh_set_error("unknown hash type for OID");
  return -1;
}

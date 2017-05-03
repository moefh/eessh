/* bignum.c */

#include <stdlib.h>
#include <stdint.h>

#include "crypto/bignum.h"

#include "common/error.h"
#include "common/buffer.h"

#define GET_DH(p) ((DH *) (p))

static uint8_t bignum_buf[MAX_BIGNUM_SIZE+1];

int crypto_string_to_bignum(BIGNUM *bn, const struct SSH_STRING *str)
{
  uint8_t *p;
  size_t len;

  // check if data is not meant to make bignum negative
  if ((str->str[0] & 0x80) != 0) {
    ssh_set_error("data would make bignum negative");
    return -1;
  }
  
  // skip leading zeros
  p = str->str;
  len = str->len;
  if (len > MAX_BIGNUM_SIZE+1 || (len == MAX_BIGNUM_SIZE+1 && (*p & 0x80) != 0)) {
    ssh_set_error("data too large for bignum");
    return -1;
  }
  while (*p == 0 && len > 0) {
    p++;
    len--;
  }

  // construct bignum
  if (BN_bin2bn(p, len, bn) == NULL) {
    ssh_set_error("out of memory");
    return -1;
  }
  return 0;
}

int crypto_bignum_to_string(const BIGNUM *bn, struct SSH_STRING *out)
{
  int bn_len = BN_num_bytes(bn);
  if (bn_len < 0 || bn_len > MAX_BIGNUM_SIZE) {
    ssh_set_error("bignum too large");
    return -1;
  }

  if (BN_bn2bin(bn, bignum_buf+1) != bn_len) {
    ssh_set_error("invalid bignum size");
    return -1;
  }

  if (bn_len > 0 && (bignum_buf[1] & 0x80) != 0) {
    bignum_buf[0] = 0;
    out->str = bignum_buf;
    out->len = bn_len + 1;
    return 0;
  }

  out->str = bignum_buf + 1;
  out->len = bn_len;
  return 0;
}

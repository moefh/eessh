/* bignum.h */

#ifndef BIGNUM_H_FILE
#define BIGNUM_H_FILE

#include <openssl/bn.h>

#include "common/buffer.h"

#define MAX_BIGNUM_SIZE (32768/8)

int crypto_string_to_bignum(BIGNUM *bn, const struct SSH_STRING *str);
int crypto_bignum_to_string(const BIGNUM *bn, struct SSH_STRING *out);

#endif /* BIGNUM_H_FILE */

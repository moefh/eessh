/* init.c */

#include <stdlib.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto/init.h"
#include "crypto/random.h"

int crypto_init(void)
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  //OPENSSL_config(NULL);

  if (crypto_random_init() < 0)
    return -1;
  return 0;
}

void crypto_deinit(void)
{
  crypto_random_deinit();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
}

/* dh.h */

#ifndef DH_H_FILE
#define DH_H_FILE

#include "common/buffer.h"

struct CRYPTO_DH;

struct CRYPTO_DH *crypto_dh_new(const char *hex_gen, const char *hex_modulus);
void crypto_dh_free(struct CRYPTO_DH *dh);
int crypto_dh_get_pubkey(struct CRYPTO_DH *crypto_dh, struct SSH_STRING *out);
int crypto_dh_compute_key(struct CRYPTO_DH *crypto_dh, struct SSH_STRING *ret_key, const struct SSH_STRING *server_pubkey);

#endif /* DH_H_FILE */

/* cipher_i.h */

#ifndef CIPHER_I_H_FILE
#define CIPHER_I_H_FILE

#include <stdint.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"

struct SSH_CIPHER_CTX;

enum SSH_CIPHER_TYPE ssh_cipher_get_by_name(const char *name);
enum SSH_CIPHER_TYPE ssh_cipher_get_by_name_n(const uint8_t *name, size_t name_len);
enum SSH_CIPHER_TYPE ssh_cipher_get_by_name_str(const struct SSH_STRING *name);
int ssh_cipher_get_supported_algos(struct SSH_BUFFER *ret);

int ssh_cipher_get_block_len(enum SSH_CIPHER_TYPE type);
int ssh_cipher_get_key_len(enum SSH_CIPHER_TYPE type);
int ssh_cipher_get_iv_len(enum SSH_CIPHER_TYPE type);

struct SSH_CIPHER_CTX *ssh_cipher_new(enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, const struct SSH_STRING *key, const struct SSH_STRING *iv);
void ssh_cipher_free(struct SSH_CIPHER_CTX *ctx);
int ssh_cipher_crypt(struct SSH_CIPHER_CTX *ctx, uint8_t *out, uint8_t *data, uint32_t len);

#endif /* CIPHER_I_H_FILE */

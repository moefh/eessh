/* random.h */

#ifndef CRYPTO_RANDOM_H_FILE
#define CRYPTO_RANDOM_H_FILE

#include <stdint.h>
#include <stddef.h>

int crypto_random_init(void);
void crypto_random_deinit(void);
int crypto_random_gen(uint8_t *data, size_t len);

#endif /* CRYPTO_RANDOM_H_FILE */

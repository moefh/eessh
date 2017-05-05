/* ssh.h */

#ifndef SSH_H_FILE
#define SSH_H_FILE

#include <stdint.h>

#include "common/error.h"
#include "common/debug.h"
#include "common/host_key_store.h"
#include "ssh/connection.h"

#define SSH_INIT_NO_SIGNALS (1<<0)

int ssh_init(uint32_t flags);
void ssh_deinit(void);

#endif /* SSH_H_FILE */


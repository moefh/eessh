/* ssh.c */

#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include "ssh/ssh.h"
#include "crypto/init.h"

int ssh_init(uint32_t flags)
{
  if ((flags & SSH_INIT_NO_SIGNALS) == 0) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
      ssh_set_error("error ignoring signal");
      return -1;
    }
  }
  
  return crypto_init();
}

void ssh_deinit(void)
{
  crypto_deinit();
}

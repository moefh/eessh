/* kex_dh.h */

#ifndef KEX_DH_H_FILE
#define KEX_DH_H_FILE

#include "ssh/kex.h"
#include "ssh/connection.h"

int ssh_kex_dh_run(struct SSH_CONN *conn, struct SSH_KEX *kex);

#endif /* KEX_DH_H_FILE */

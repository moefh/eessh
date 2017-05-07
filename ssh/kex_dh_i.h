/* kex_dh_i.h */

#ifndef KEX_DH_I_H_FILE
#define KEX_DH_I_H_FILE

#include "ssh/kex_i.h"
#include "ssh/connection.h"

int ssh_kex_dh_run(struct SSH_CONN *conn, struct SSH_KEX *kex);

#endif /* KEX_DH_I_H_FILE */

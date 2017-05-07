/* userauth_i.h */

#ifndef USERAUTH_I_H_FILE
#define USERAUTH_I_H_FILE

#include "ssh/connection.h"

int ssh_userauth_run(struct SSH_CONN *conn);

#endif /* USERAUTH_I_H_FILE */

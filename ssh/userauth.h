/* userauth.h */

#ifndef USERAUTH_H_FILE
#define USERAUTH_H_FILE

#include "ssh/connection.h"

int ssh_userauth_run(struct SSH_CONN *conn);

#endif /* USERAUTH_H_FILE */

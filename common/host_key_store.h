/* host_key_store.h */

#ifndef HOST_KEY_STORE_H_FILE
#define HOST_KEY_STORE_H_FILE

#include "common/buffer.h"

enum SSH_HOST_KEY_STORE_STATUS {
  SSH_HOST_KEY_STORE_STATUS_OK,                 // host key verified
  SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND,      // host is not in store
  SSH_HOST_KEY_STORE_STATUS_ERR_BAD_IDENTITY,   // given host key doesn't match stored host key
  SSH_HOST_KEY_STORE_STATUS_ERR_OTHER           // other error (use ssh_get_error() to get message)
};

int ssh_host_key_store_add(const char *filename, const char *hostname, const struct SSH_STRING *server_host_key);
enum SSH_HOST_KEY_STORE_STATUS ssh_host_key_store_check_server(const char *filename, const char *hostname, const struct SSH_STRING *server_host_key);

#endif /* HOST_KEY_STORE_H_FILE */

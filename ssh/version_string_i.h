/* version_string_i.h */

#ifndef VERSION_STRING_I_H_FILE
#define VERSION_STRING_I_H_FILE

#include "ssh/version_string.h"

int ssh_version_string_read(struct SSH_VERSION_STRING *ver_str, int sock, struct SSH_BUFFER *rest);
int ssh_version_string_build(struct SSH_VERSION_STRING *ver_str, const char *software, const char *comments);

#endif /* VERSION_STRING_I_H_FILE */

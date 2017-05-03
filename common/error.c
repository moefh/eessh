/* error.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include "common/error.h"

#define ABORT_ON_ERROR 0

static char error_msg[1024];

const char *ssh_get_error(void)
{
  return error_msg;
}

void ssh_set_error(const char *fmt, ...)
{
  va_list ap;
  
  va_start(ap, fmt);
  vsnprintf(error_msg, sizeof(error_msg), fmt, ap);
  va_end(ap);

#if ABORT_ON_ERROR
  printf("ABORTING ON ERROR: %s\n", error_msg);
  abort();
#endif
}

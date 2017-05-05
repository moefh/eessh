/* alloc.c */

#include <stdlib.h>

#include "common/alloc.h"

#include "common/error.h"

void *ssh_alloc(size_t size)
{
  void *ret = calloc(1, size);
  if (ret == NULL)
    ssh_set_error("out of memory");
  return ret;
}

void *ssh_realloc(void *p, size_t size)
{
  void *ret = realloc(p, size);
  if (ret == NULL)
    ssh_set_error("out of memory");
  return ret;
}

void ssh_free(void *p)
{
  free(p);
}

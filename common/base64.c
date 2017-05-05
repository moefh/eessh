/* base64.c */

#include <stdlib.h>
#include <stdint.h>

#include "common/base64.h"

#include "common/error.h"
#include "common/alloc.h"

const uint8_t base64_table[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/";


char *base64_encode(uint8_t *data, size_t data_len)
{
  uint8_t *cur = (uint8_t *) data;
  uint8_t *end = (uint8_t *) data + (data_len/3)*3;
  uint8_t *ret;
  uint8_t *out;

  ret = ssh_alloc((data_len/3)*4 + ((data_len%3==0) ? 0 : (3-data_len%3)) + 1);
  if (ret == NULL)
    return NULL;
  
  out = ret;
  while (cur < end) {
    *out++ = base64_table[cur[0]>>2];
    *out++ = base64_table[((cur[0]<<4) & 0x3f) | (cur[1]>>4)];
    *out++ = base64_table[((cur[1]<<2) & 0x3f) | (cur[2]>>6)];
    *out++ = base64_table[cur[2] & 0x3f];
    cur += 3;
  }

  switch (3 - data_len % 3) {
  case 1:
    *out++ = base64_table[cur[0]>>2];
    *out++ = base64_table[((cur[0]<<4) & 0x3f) | (cur[1]>>4)];
    *out++ = base64_table[((cur[1]<<2) & 0x3f)];
    *out++ = '=';
    break;
    
  case 2:
    *out++ = base64_table[cur[0]>>2];
    *out++ = base64_table[((cur[0]<<4) & 0x3f)];
    *out++ = '=';
    *out++ = '=';
    break;
  }
  *out = '\0';

  return (char *) ret;
}

#if 0
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
  if (argc < 2) {
    printf("USO: base64 string\n");
    return 1;
  }
  puts(base64_encode((uint8_t *) argv[1], strlen(argv[1])));
  return 0;
}
#endif

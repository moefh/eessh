/* random.c */

#include <stdlib.h>

#include "crypto/random.h"
#include "common/error.h"

#define USE_GETRANDOM

#if defined(USE_ARC4)

int crypto_random_init(void) { return 0; }
void crypto_random_deinit(void) {}
int crypto_random_gen(uint8_t *data, size_t len)
{
  arc4random_buf(data, len);
  return 0;
}

#elif defined(USE_GETRANDOM)

#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>
#include <errno.h>

int crypto_random_init(void) { return 0; }
void crypto_random_deinit(void) {}

int crypto_random_gen(uint8_t *data, size_t len)
{
  size_t s = 0;

  while (s < len) {
    //int r = getrandom(data + s, len - s, 0);
    int r = syscall(SYS_getrandom, data + s, len - s, 0u);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0) {
      ssh_set_error("getrandom() returns error (errno=%d)", errno);
      return -1;
    }
    s += r;
  }
  
  return 0;
}

#elif defined(USE_URANDOM)

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

static int dev_urandom_fd = -1;

int crypto_random_init(void)
{
  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) {
    ssh_set_error("can't open /dev/urandom");
    return -1;
  }
  return 0;
}

void crypto_random_deinit(void)
{
  if (dev_urandom_fd >= 0) {
    close(dev_urandom_fd);
    dev_urandom_fd = -1;
  }
}

int crypto_random_gen(uint8_t *data, size_t len)
{
  size_t s = 0;

  while (s < len) {
    ssize_t r = read(dev_urandom_fd, data + s, len - s);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0) {
      ssh_set_error("error reading /dev/urandom");
      return -1;
    }
    s += r;
  }
  
  return 0;
}

#else

#error "No random method selected!"

#endif


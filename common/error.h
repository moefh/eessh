/* error.h */

#ifndef ERROR_H_FILE
#define ERROR_H_FILE

const char *ssh_get_error(void);
void ssh_set_error(const char *fmt, ...)  __attribute__ ((format (printf, 1, 2)));

#endif /* ERROR_H_FILE */

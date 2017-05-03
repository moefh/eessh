/* alloc.h */

#ifndef ALLOC_H_FILE
#define ALLOC_H_FILE

void *ssh_alloc(size_t size);
void *ssh_realloc(void *p, size_t size);
void ssh_free(void *p);

#endif /* ALLOC_H_FILE */

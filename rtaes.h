#ifndef PROC_H
#define PROC_H

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/* ----------  ---------- */

#define MAGIC_NUM 0xBEBEBEBEU

#define BLOCK_SIZE 4096

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

/* ----------  ---------- */

int encrypt_file ( FILE* in_file, FILE* out_file, size_t length, uint8_t* key, uint32_t* checksum );

int decrypt_file ( FILE* in_file, FILE* out_file, size_t length, uint8_t* key, uint32_t* checksum );



#endif /* PROC_H */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "rtaes.h"

/* ----------  ---------- */

static inline const char* get_name_from_path ( const char* path ) {
  
  const char* name = path;
  
  for ( const char* p = name + 1; *p != '\0'; p++ ) {
    if ( *(p - 1) == '/' ) name = p;
  }
  
  return name;
}

const char* prog_name = NULL;

static inline void set_prog_name ( const char* inv_path ) {
  
  assert ( (inv_path != NULL) && (*inv_path != '\0') );
  
  prog_name = get_name_from_path (inv_path);
  
  return;
}

static void print_usage ( void ) {
  
  const char text[] = "Usage: %s [-ed] INPATH OUTDIR KEY  - encrypt/decrypt file\n"
                      "       %s -h                       - display help\n";
  
  fprintf ( stderr, text, prog_name, prog_name );
  
  return;
}

static void print_help ( void ) {
  
  const char text[] = 
      "\n%s - AES Encryptor/Decryptor tool\n\n"
      "Parameters: INPATH - path to input file\n"
      "            OUTDIR - output directory\n"
      "            KEY    - key as string\n";
  
  fprintf ( stderr, text, prog_name );
  
  return;
}

/* ----------  ---------- */

static int create_encrypt_output_path ( const char* in_path, const char* out_dir, char* out_path ) {
  
  assert ( (in_path != NULL) && (*in_path != '\0') );
  assert ( (out_dir != NULL) && (*out_dir != '\0') );
  assert (out_path != NULL);
  
  /* -----  ----- */
  
  size_t cnt = snprintf ( out_path, PATH_MAX - 1, "%s/%s.enc", out_dir, get_name_from_path (in_path) );
  
  if ( cnt >= (PATH_MAX - 1) ) return 1;
  
  return 0;
}

static int create_decrypt_output_path ( const char* in_path, const char* out_dir, char* out_path ) {
  
  assert ( (in_path != NULL) && (*in_path != '\0') );
  assert ( (out_dir != NULL) && (*out_dir != '\0') );
  assert (out_path != NULL);
  
  /* -----  ----- */
  
  const char* name = get_name_from_path (in_path);
  
  size_t nl = strlen (name);
  if (nl < 5) return 1;
  if ( strcmp ( (name + nl - 4), ".enc" ) ) return 1; // isn't "*.enc"
  nl -= 4;
  
  size_t pl = strlen (out_dir);
  if ( (nl + pl + 2) >= PATH_MAX ) return 2;
  
  memcpy ( out_path, out_dir, pl );
  out_path[pl] = '/';
  memcpy ( (out_path + pl + 1), name, nl );
  out_path[pl + 1 + nl] = '\0';
  
  return 0;
}

/* ----------  ---------- */

int encrypt ( const char* in_path, const char* out_path, const char* key_str ) {
  
  assert ( (in_path != NULL) && (*in_path != '\0') );
  assert ( (out_path != NULL) && (*out_path != '\0') );
  assert ( (key_str != NULL) && (*key_str != '\0') );
  
  /* -----  ----- */
  
  FILE* ifs = fopen (in_path, "r");
  if (ifs == NULL) return 1;
  
  fseek (ifs, 0, SEEK_END);
  size_t len = ftell (ifs);
  fseek (ifs, 0, SEEK_SET);
  
  /* -----  ----- */
  
  FILE* ofs = fopen (out_path, "w");
  if (ofs == NULL) return 2;
  
  uint8_t head[16];
  memset (head, 0, 16);
  if ( fwrite ( head, 1, 16, ofs ) != 16 ) return 3;
  
  /* -----  ----- */
  
  uint8_t key[32];
  memset (key, 0, 32);
  
  for (size_t i = 0; i < strlen (key_str); i++) {
    key[i % 32] = (uint8_t)key_str[i];
  }
  
  /* -----  ----- */
  
  uint32_t cks = 0;
  int res = 0;
  
  res = encrypt_file ( ifs, ofs, len, key, &cks );
  if (res != 0) return res; // close fsteams ?
  
  /* -----  ----- */
  
  fseek (ofs, 0, SEEK_SET);
  
  uint32_t mn = (uint32_t)MAGIC_NUM;
  uint64_t sz = (uint64_t)len;
  
  for (int i = 0; i < 4; i++) {
    head[i] = (uint8_t)((mn >> (8 * i)) & 0xFF); // write LE
  }
  for (int i = 0; i < 8; i++) {
    head[4 + i] = (uint8_t)((sz >> (8 * i)) & 0xFF);
  }
  for (int i = 0; i < 4; i++) {
    head[12 + i] = (uint8_t)((cks >> (8 * i)) & 0xFF);
  }
  
  if ( fwrite ( head, 1, 16, ofs ) != 16 ) return 3;
  
  /* -----  ----- */
  
  printf ("Encryption success:\n"
          "  Length: %zu\n"
          "  Checksum: 0x%08X\n",
          len, cks);
  
  /* -----  ----- */
  
  fclose (ifs);
  fclose (ofs);
  
  return 0;
}

int decrypt ( const char* in_path, const char* out_path, const char* key_str ) {
  
  assert ( (in_path != NULL) && (*in_path != '\0') );
  assert ( (out_path != NULL) && (*out_path != '\0') );
  assert ( (key_str != NULL) && (*key_str != '\0') );
  
  /* -----  ----- */
  
  FILE* ifs = fopen (in_path, "r");
  if (ifs == NULL) return 1;
  
  uint8_t head[16];
  if ( fread ( head, 1, 16, ifs ) != 16 ) return 2;
  
  /* ----- read header ----- */
  
  uint32_t mn = 0;
  for (int i = 0; i < 4; i++) {
    mn <<= 8;
    mn |= (uint32_t)head[3 - i]; // read LE
  }
  if (mn != (uint32_t)MAGIC_NUM) return 3;
  
  uint64_t sz = 0;
  for (int i = 0; i < 8; i++) {
    sz <<= 8;
    sz |= (uint64_t)head[11 - i];
  }
  size_t len = sz;
  
  uint32_t scks = 0;
  for (int i = 0; i < 4; i++) {
    scks <<= 8;
    scks |= (uint32_t)head[15 - i];
  }
  
  /* -----  ----- */
  
  printf ("Decryption begin:\n"
          "  Length: %zu\n"
          "  Checksum: 0x%08X\n", 
          len, scks);
  
  /* -----  ----- */
  
  FILE* ofs = fopen (out_path, "w");
  if (ofs == NULL) return 4;
  
  uint8_t key[32];
  memset (key, 0, 32);
  
  for (size_t i = 0; i < strlen (key_str); i++) {
    key[i % 32] = (uint8_t)key_str[i];
  }
  
  uint32_t ccks = 0;
  
  /* -----  ----- */
  
  int res = decrypt_file ( ifs, ofs, len, key, &ccks );
  if (res != 0) return res;
  
  if (scks != ccks) return 5;
  
  /* -----  ----- */
  
  printf ("Decryption succes !\n");
  
  /* -----  ----- */
  
  fclose (ifs);
  fclose (ofs);
  
  return 0;
}

/* ----------  ---------- */

int main (int arg_cnt, char** arg_vec) {
  
  int mode = 0, res;
  char opath[PATH_MAX + 1];
  
  set_prog_name (arg_vec[0]);
  
  
  if ( (arg_cnt == 2) && (! strcmp (arg_vec[1], "-h") ) ) {
    print_usage ();
    print_help ();
    return (EXIT_SUCCESS);
  }
  
  if (arg_cnt == 5) {
    if (! strcmp (arg_vec[1], "-e") ) mode = 'e';
    if (! strcmp (arg_vec[1], "-d") ) mode = 'd';
  }
  
  if (mode == 0) {
    fprintf ( stderr, "error: invalid input arguments\n" );
    print_usage ();
    return (EXIT_FAILURE);
  }
  
//  check ".bin" extension ?
//  check (inpath != outpath) !
  
  if (mode == 'e') {
    
    res = create_encrypt_output_path ( arg_vec[2], arg_vec[3], opath );
    if (res != 0) {
      fprintf ( stderr, "error: invalid path #%d\n", res );
      return (EXIT_FAILURE);
    }
    
    res = encrypt ( arg_vec[2], opath, arg_vec[4] );
    if (res != 0) {
      fprintf ( stderr, "error: encryption failure #%d\n", res );
      return (EXIT_FAILURE);
    }
  }
  
  
  if (mode == 'd') {
    
    res = create_decrypt_output_path ( arg_vec[2], arg_vec[3], opath );
    if (res != 0) {
      fprintf ( stderr, "error: invalid path #%d\n", res );
      return (EXIT_FAILURE);
    }
    
    res = decrypt ( arg_vec[2], opath, arg_vec[4] );
    if (res != 0) {
      fprintf ( stderr, "error: decryption failure #%d\n", res );
      return (EXIT_FAILURE);
    }
  }
  
  
  return (EXIT_SUCCESS);
}



#ifndef _PGEN_H_
#define _PGEN_H_

#include "Arduino.h"
#include "aes256.h"
#include "sha256.h"

/*
 * Flags for the pwgen function
 */
#define PW_WEAK     0x0000  /* All lower */
#define PW_DIGITS   0x0001  /* At least one digit */
#define PW_UPPERS   0x0002  /* At least one upper letter */
#define PW_SYMBOLS  0x0004
#define PW_STRONG  (PW_DIGITS|PW_UPPERS|PW_SYMBOLS)

class pgen_
{
private:
  aes256_context ctxt;
  int shasum_idx;
  uint8_t my_key[32];
  uint8_t my_data[32];
  uint8_t pw_sha_number(uint8_t max_num);
public:
  pgen_(void);
  void init(uint8_t *key);
  void feed(uint8_t *data);
  char generate(char *buf, int size, int pw_flags);
  void clear(void);
};
extern pgen_ pgen;

#endif


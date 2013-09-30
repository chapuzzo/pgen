#include "Arduino.h"
#include "pgen.h"

const char *pw_digits = "0123456789";
const char *pw_uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char *pw_lowers = "abcdefghijklmnopqrstuvwxyz";
const char *pw_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}`";

void printHash(uint8_t* hash) {
  int i;
  for (i=0; i<32; i++) {
    Serial.print("0123456789abcdef"[hash[i]>>4]);
    Serial.print("0123456789abcdef"[hash[i]&0xf]);
  }
  Serial.println();
}

pgen_::pgen_(void){
    shasum_idx=32;
}

void pgen_::init(uint8_t *key){
    Sha256.init();
    Sha256.print((char*)key);
    memcpy(my_key, Sha256.result(), 32);
    aes256_init(&ctxt,key);
}

void pgen_::feed(uint8_t *data){
    Sha256.init();
    Sha256.print((char*)data);
    memcpy(my_data, Sha256.result(), 32);
    aes256_encrypt_ecb(&ctxt, my_data);
    //aes256_done(&ctxt);
}


void pgen_::clear(void){
    shasum_idx=32;
}

const char *sha_magic="minervaguapa";

uint8_t pgen_::pw_sha_number(uint8_t max_num){
    uint8_t val=0;
    if (shasum_idx>31) {
        shasum_idx = 0;
        Sha256.print(sha_magic);
    }
    val = (int) (Sha256.result()[shasum_idx++] / ((float) 256) * max_num);
    //val = (Sha256.result()[shasum_idx++])%max_num;
    return val;
}


char pgen_::generate(char *buf, int size, int pw_flags)
{
    char    ch, *chars, *wchars, feature_flags;
    int     i, len;
    shasum_idx = 31;
    len = 0;
    if (pw_flags & PW_DIGITS) {
        len += strlen(pw_digits);
    }
    if (pw_flags & PW_UPPERS) {
        len += strlen(pw_uppers);
    }
    len += strlen(pw_lowers);
    if (pw_flags & PW_SYMBOLS) {
        len += strlen(pw_symbols);
    }
        chars = (char*) calloc(len+1,sizeof(char));
        if (!chars) {
            return 0;
        }
    wchars = chars;
    if (pw_flags & PW_DIGITS) {
        strcpy(wchars, pw_digits);
        wchars += strlen(pw_digits);
    }
    if (pw_flags & PW_UPPERS) {
        strcpy(wchars, pw_uppers);
        wchars += strlen(pw_uppers);
    }
    strcpy(wchars, pw_lowers);
    wchars += strlen(pw_lowers);
    if (pw_flags & PW_SYMBOLS) {
        strcpy(wchars, pw_symbols);
    }
try_again:
    len = strlen(chars);
    feature_flags = pw_flags;
    i = 0;
    while (i < size) {
        ch = chars[pw_sha_number(len)];
        buf[i++] = ch;
        if (strchr(pw_digits, ch))
            feature_flags &= ~PW_DIGITS;
        if (strchr(pw_uppers, ch))
            feature_flags &= ~PW_UPPERS;
        if (strchr(pw_symbols, ch))
            feature_flags &= ~PW_SYMBOLS;
    }
    if (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS))
        goto try_again;
    buf[size] = 0;
    free(chars);
    return 1;
}
pgen_ pgen;

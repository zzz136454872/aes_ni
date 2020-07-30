// 
#ifndef aes_h

#include<wmmintrin.h>

void aes_128_enc_block(unsigned char *plain,unsigned char* cipher,(unsigned char* subkey)[128]);
void aes_128_dec(unsigned char *cipher,unsigned char *plain,(unsigned char*subkey[128]);
void aes_128_key_expansion(unsigned char* key,(unsigned char* subkey)[128]);

#endif


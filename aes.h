#ifndef aes_h
#include<immintrin.h>

void aes_128_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char* subkey);
void aes_128_dec(unsigned char *cipher,unsigned char *plain,unsigned char* subkey);
void aes_128_key_expansion(unsigned char* 

#endif



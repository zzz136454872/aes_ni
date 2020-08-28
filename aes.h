// 
#ifndef aes_h

#include<wmmintrin.h>
#include<emmintrin.h>
#include<string.h>

void aes_128_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char (*subkey)[16]);

void aes_128_dec_block(unsigned char *cipher,unsigned char *plain,unsigned char(*subkey)[16]);

void aes_128_key_expansion(unsigned char* key,unsigned char(* subkey)[16]);

#endif


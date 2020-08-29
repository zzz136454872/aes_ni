#ifndef aes_h

#include<wmmintrin.h>
#include<emmintrin.h>
#include<string.h>

//bits -> nk
//128  -> 4
//192  -> 6
//256  -> 8
void aes_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char (*subkey)[16],unsigned char nk);
void aes_dec_block(unsigned char *cipher,unsigned char *plain,unsigned char(*subkey)[16],unsigned char nk);
void aes_key_expansion(unsigned char* key,unsigned char(* subkey)[16],unsigned char nk);

void aes_128_key_expansion(unsigned char* key,unsigned char(* subkey)[16]);
void aes_192_key_expansion(unsigned char* key,unsigned char(* subkey)[16]);
void aes_256_key_expansion(unsigned char* key,unsigned char(* subkey)[16]);

#endif


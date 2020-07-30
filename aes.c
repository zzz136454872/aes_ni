#include"aes.h"

unsigned char rcon[14]={0x00/* a padding */,
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
//TODO add 10~13 for aes 192 and 256

void aes_128_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char (*subkey)[16]);

void aes_128_dec(unsigned char *cipher,unsigned char *plain,unsigned char (*subkey)[16]);

void aes_128_key_expansion(unsigned char* key,unsigned char (* subkey)[16])
{
    int i=0;
    unsigned int tmp_int;
    int *pi=(int*)(subkey+1);
    memcpy(subkey[0],key,16);
    __m128i tmp;
    for(i=4;i<44;i++)
    {
        if(i%4!=0)
            pi[i]=pi[i-1]^pi[i-4];
    }
}




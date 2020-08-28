#include"aes.h"

const unsigned char rcon[14]={0x00/* a padding */,
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
//TODO add 10~13 for aes 192 and 256

void aes_128_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char (*subkey)[16])
{
    __m128i process=_mm_loadu_si128((__m128i*)plain);
    __m128i round_key=_mm_loadu_si128((__m128i*)subkey);
    process=_mm_xor_si128(process,round_key);
    int i;
    for(i=1;i<10;i++)
    {
        round_key=_mm_loadu_si128((__m128i*)subkey+i);
        process=_mm_aesenc_si128(process,round_key);
    }
    round_key=_mm_loadu_si128((__m128i*)subkey+10);
    process=_mm_aesenclast_si128(process,round_key);
    _mm_storeu_si128((__m128i*)cipher,process);
}

void aes_128_dec_block(unsigned char *cipher,unsigned char *plain,unsigned char (*subkey)[16])
{
    __m128i process=_mm_loadu_si128((__m128i*)cipher);
    __m128i round_key=_mm_loadu_si128((__m128i*)subkey+10);
    process=_mm_xor_si128(process,round_key);
    int i;
    for(i=9;i>0;i--)
    {
        round_key=_mm_loadu_si128((__m128i*)subkey+i);
        round_key=_mm_aesimc_si128(round_key);
        process=_mm_aesdec_si128(process,round_key);
    }
    round_key=_mm_loadu_si128((__m128i*)subkey);
    process=_mm_aesdeclast_si128(process,round_key);
    _mm_storeu_si128((__m128i*)plain,process);
}

void aes_128_key_expansion(unsigned char* key,unsigned char (* subkey)[16])
{
    unsigned int buffer[4];
    unsigned int *pi=(unsigned int*)subkey;
    unsigned char tmp_char;
    memcpy(subkey[0],key,16);
    __m128i tmp;
    int i=4;
    //round1
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x01);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round2
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x02);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round3
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x04);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round4
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x08);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round5
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x10);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round6
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x20);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round7
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x40);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round8
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x80);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round9
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x1b);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    //round10
    tmp=_mm_set1_epi32(pi[i-1]);
    tmp_char=rcon[i/4];
    tmp=_mm_aeskeygenassist_si128(tmp,0x36);
    _mm_storeu_si128((__m128i*)buffer,tmp);
    pi[i++]=pi[i-4]^buffer[1];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
    pi[i++]=pi[i-1]^pi[i-4];
}



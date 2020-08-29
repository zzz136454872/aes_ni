#include"aes.h"
#include<windows.h>
#include<stdio.h>

//print memory
//start: start address
//len: length of memory to be printed
//info: a message string 
void printmem(const void * const start, const int len, const char* info) 
{
    unsigned char *ptr = (unsigned char*)start;
    int i;
    printf("%s",info);
    for(i=0;i<len;i++)
    {
        if(i%16==0)
            putchar('\n');
        printf("%02x ",ptr[i]);
    }
    putchar('\n');
}

// test the running time for a (or a group of) function 
long long nstimer()
{
    LARGE_INTEGER time_start;	
    LARGE_INTEGER time_over;	
    LARGE_INTEGER pcFrequency;
    QueryPerformanceFrequency(&pcFrequency);
    QueryPerformanceCounter(&time_start);	

    // the function to be tested 
    // TODO test speed

    QueryPerformanceCounter(&time_over);
    long long run_time=(long long)1000000000*(time_over.QuadPart-time_start.QuadPart)/pcFrequency.QuadPart; 
    // running time (in nanoseconds)
    printf("run_time: %I64d ns\n",run_time);
    return run_time;
}

// a test key
unsigned char key128[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

unsigned char key192[24]={0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};

unsigned char key256[32];

// the buffer for round key
unsigned char subkey[15][16];
unsigned char plain[32]={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};

unsigned char cipher[32];
unsigned char decrypt[32];

int main()
{
    //test of aes 128
    printmem(key128,16,"key");
    aes_128_key_expansion(key128,subkey);
    printmem(subkey,240,"subkey128");
    aes_enc_block(plain,cipher,subkey,4);
    printmem(plain,16,"plain");
    printmem(cipher,16,"cipher");
    aes_dec_block(cipher,decrypt,subkey,4);
    printmem(decrypt,16,"decrypted");
    //test of aes 192
    printmem(key192,24,"key");
    aes_192_key_expansion(key192,subkey);
    printmem(subkey,240,"subkey192");
    aes_enc_block(plain,cipher,subkey,6);
    printmem(plain,16,"plain");
    printmem(cipher,16,"cipher");
    aes_dec_block(cipher,decrypt,subkey,6);
    printmem(decrypt,16,"decrypted");
    //test of aes 256
    return 0;
}


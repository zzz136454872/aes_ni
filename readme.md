# An AES block cipher with AES-NI Intrinsics

## structure
1. aes.c: the implementation
2. aes.h: the header file
3. test.c: the test functions
4. makefile: the compile instructions

## functions
### 128bits AES

1. void aes_128_key_expansion(unsigned char* key,unsigned char (* subkey)[16])
2. void aes_128_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char (*subkey)[16])
3. void aes_128_dec_block(unsigned char *cipher,unsigned char *plain,unsigned char (*subkey)[16])

not finished yet!


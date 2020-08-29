# An AES block cipher with AES-NI Intrinsics

##### an aes library programmed in C, with the help of AES-NI the spped can be very fast. 

## structure
1. aes.c: the implementation
2. aes.h: the header file
3. test.c: the test functions
4. makefile: the compile instructions

## functions

### key expansion 
1. `void aes_128_key_expansion(unsigned char* key,unsigned char (* subkey)[16])`
2. `void aes_192_key_expansion(unsigned char* key,unsigned char (* subkey)[16])`
3. `void aes_256_key_expansion(unsigned char* key,unsigned char (* subkey)[16])`

and a more convenient one is:

`void aes_256_key_expansion(unsigned char* key,unsigned char (* subkey)[16],unsigned char nk)`

where nk represents the length of the key.

| nk | key length(bits) |
| --- | ---  | 
| 4 | 128 | 
| 6 | 192 | 
| 8 | 256 | 

### encrypt 
`void aes_enc_block(unsigned char *plain,unsigned char* cipher,unsigned char (*subkey)[16],unsigned char nk);`

### decrypt
`void aes_dec_block(unsigned char *cipher,unsigned char *plain,unsigned char(*subkey)[16],unsigned char nk);`

### compile commands

can be found in makefile. 




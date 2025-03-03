/*
*License

The MIT License (MIT)

Copyright (c) 2016 lxd.me

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*/

#ifndef _SECURITY_H_
#define _SECURITY_H_
#include <memory.h>
#include <openssl/aes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define AES_128 128
#define KEY_BYTE_LEN 16
#define IV_BYTE_LEN 16
typedef struct Crypter {
  unsigned char indata[AES_BLOCK_SIZE];
  unsigned char outdata[AES_BLOCK_SIZE];
  unsigned char decryptdata[AES_BLOCK_SIZE];
  unsigned char userkey[KEY_BYTE_LEN];
  unsigned char ivec[IV_BYTE_LEN];
  AES_KEY key;
} Crypter;

int i_encrypt(unsigned char *plain_text, unsigned char *cipher_text,
              size_t plain_text_sz, struct Crypter crypt);
int i_decrypt(unsigned char *cipher_text, unsigned char *plain_text,
              size_t cipher_text_sz, struct Crypter crypt);

#endif

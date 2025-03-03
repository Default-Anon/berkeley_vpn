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

#include "headers/security.h"
int i_encrypt(unsigned char *plain_text, unsigned char *cipher_text,
              size_t plain_text_sz, struct Crypter crypt) {
  int postion = 0;
  int bytes_write = 0;
  int divider = 0;
  unsigned char *plain_text_ptr = plain_text;
  unsigned char *cipher_text_ptr = cipher_text;
  while (plain_text_sz / AES_BLOCK_SIZE) {
    memcpy(crypt.indata, plain_text_ptr, AES_BLOCK_SIZE);
    plain_text_ptr += AES_BLOCK_SIZE;
    AES_cfb128_encrypt(crypt.indata, crypt.outdata, AES_BLOCK_SIZE, &crypt.key,
                       crypt.ivec, &postion, AES_ENCRYPT);
    memcpy(cipher_text_ptr, crypt.outdata, AES_BLOCK_SIZE);
    bytes_write += AES_BLOCK_SIZE;
    cipher_text_ptr += AES_BLOCK_SIZE;
    plain_text_sz -= AES_BLOCK_SIZE;
  }
  divider = plain_text_sz % AES_BLOCK_SIZE;
  memcpy(crypt.indata, plain_text_ptr, AES_BLOCK_SIZE);
  AES_cfb128_encrypt(crypt.indata, crypt.outdata, divider, &crypt.key,
                     crypt.ivec, &postion, AES_ENCRYPT);
  memcpy(cipher_text_ptr, crypt.outdata, divider);
  bytes_write += divider;
  return bytes_write;
}
int i_decrypt(unsigned char *cipher_text, unsigned char *plain_text,
              size_t cipher_text_sz, struct Crypter crypt) {
  int postion = 0;
  int bytes_write = 0;
  int divider = 0;
  unsigned char *plain_text_ptr = plain_text;
  unsigned char *cipher_text_ptr = cipher_text;
  while (cipher_text_sz / AES_BLOCK_SIZE) {
    memcpy(crypt.outdata, cipher_text_ptr, AES_BLOCK_SIZE);
    cipher_text_ptr += AES_BLOCK_SIZE;
    AES_cfb128_encrypt(crypt.outdata, crypt.decryptdata, AES_BLOCK_SIZE,
                       &crypt.key, crypt.ivec, &postion, AES_DECRYPT);
    memcpy(plain_text_ptr, crypt.decryptdata, AES_BLOCK_SIZE);
    plain_text_ptr += AES_BLOCK_SIZE;
    bytes_write += AES_BLOCK_SIZE;
    cipher_text_sz -= AES_BLOCK_SIZE;
  }
  divider = cipher_text_sz % AES_BLOCK_SIZE;
  memcpy(crypt.outdata, cipher_text_ptr, AES_BLOCK_SIZE);
  AES_cfb128_encrypt(crypt.outdata, crypt.decryptdata, divider, &crypt.key,
                     crypt.ivec, &postion, AES_DECRYPT);
  memcpy(plain_text_ptr, crypt.decryptdata, divider);
  bytes_write += divider;
  return bytes_write;
}

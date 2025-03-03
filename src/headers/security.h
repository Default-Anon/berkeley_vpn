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

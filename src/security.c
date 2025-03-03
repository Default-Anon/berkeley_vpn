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

#include <memory.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sprd_sign.h"

struct dhtb_header {
  uint64_t magic;
  uint8_t unused1[40];
  uint32_t payload_size;
  uint8_t unused2[460];
} __attribute__((packed));

RSA *sprdsign_rsa_deserialize(const struct sprdsign_rsa_pubkey *data) {
  if (data->bits >> 3 > sizeof(data->n))
    return NULL;
  BIGNUM *e = BN_bin2bn((uint8_t *)&data->e, 4, NULL);
  BIGNUM *n = BN_bin2bn(data->n, data->bits >> 3, NULL);
  RSA *key = RSA_new_public_key(n, e);
  BN_free(e);
  BN_free(n);
  return key;
}

RSA *sprdsign_get_default_privkey() {
  BIGNUM *n = BN_bin2bn(sprdsign_default_privkey_n,
                        sizeof(sprdsign_default_privkey_n), NULL);
  BIGNUM *e = BN_bin2bn(sprdsign_default_privkey_e,
                        sizeof(sprdsign_default_privkey_e), NULL);
  BIGNUM *d = BN_bin2bn(sprdsign_default_privkey_d,
                        sizeof(sprdsign_default_privkey_d), NULL);
  RSA *key = RSA_new_private_key_no_crt(n, e, d);
  BN_free(n);
  BN_free(e);
  BN_free(d);
  return key;
}

int sprdsign_verify_signature(const struct sprd_content_signature *signature,
                              RSA *key) {
  if (signature->signature_type != 0)
    return 0;
  RSA *pubkey = key;
  if (!key)
    pubkey = sprdsign_rsa_deserialize(&signature->pubkey);
  if (!pubkey)
    return 0;
  size_t key_size = RSA_size(pubkey);
  uint8_t *decrypted = (uint8_t *)malloc(key_size);
  if (!decrypted)
    return 0;

  RSA_public_decrypt(key_size, signature->signature, decrypted, pubkey,
                     RSA_PKCS1_PADDING);
  int result = memcmp(signature->checksum, decrypted,
                      sizeof(signature->checksum) + sizeof(signature->type) +
                          sizeof(signature->anti_rollback_version)) == 0;
  free(decrypted);
  if (!key)
    RSA_free(pubkey);
  return result;
}

int sprdsign_sign_signature(struct sprd_content_signature *signature,
                            RSA *private_key) {
  return RSA_private_encrypt(sizeof(signature->checksum) +
                                 sizeof(signature->type) +
                                 sizeof(signature->anti_rollback_version),
                             signature->checksum, signature->signature,
                             private_key, RSA_PKCS1_PADDING);
}

/*
int sprdsign_is_default_key(const RSA *public_key) {
  const BIGNUM *e = RSA_get0_e(public_key);
  const BIGNUM *n = RSA_get0_n(public_key);
  BIGNUM *default_e = BN_bin2bn(sprdsign_default_privkey_e,
                                sizeof(sprdsign_default_privkey_e), NULL);
  BIGNUM *default_n = BN_bin2bn(sprdsign_default_privkey_n,
                                sizeof(sprdsign_default_privkey_n), NULL);

  int result = BN_equal_consttime(e, default_e) == 1;
  result += BN_equal_consttime(n, default_n) == 1;

  BN_free(default_e);
  BN_free(default_n);

  return result == 2;
}
*/

int sprdsign_check_footer(struct sprd_footer *footer, size_t payload_size,
                          size_t total_size) {
  if (footer->payload_size != payload_size ||
      footer->payload_offset != sizeof(struct dhtb_header) ||
      footer->signature_size != sizeof(struct sprd_content_signature) ||
      footer->private_size != 0 || footer->private_offset != 0 ||
      footer->dbg_signature_primary_size != 0 ||
      footer->dbg_signature_primary_offset != 0 ||
      footer->dbg_signature_devloper_size != 0 ||
      footer->dbg_signature_devloper_offset != 0 ||
      total_size < footer->signature_offset + footer->signature_size)
    return 0;
  return 1;
}

int sprdsign_verify(void *image, size_t size, RSA *validate_key) {
  void *addr = image;
  if (size < sizeof(struct dhtb_header))
    return 0;
  struct dhtb_header *header = image;
  // boothead
  if (header->magic != 5407787076 ||
      header->payload_size > sizeof(struct dhtb_header) + size)
    return 0;

  addr += sizeof(struct dhtb_header);
  uint8_t checksum[SHA256_DIGEST_LENGTH];
  SHA256(addr, header->payload_size, checksum);

  if (size < sizeof(struct dhtb_header) + header->payload_size +
                 sizeof(struct sprd_footer))
    return 0;
  addr += header->payload_size;
  struct sprd_footer *footer = addr;

  if (!sprdsign_check_footer(footer, header->payload_size, size))
    return 0;

  struct sprd_content_signature *signature = image + footer->signature_offset;
  if (memcmp(checksum, signature->checksum, SHA256_DIGEST_LENGTH))
    return 0;
  if (!sprdsign_verify_signature(signature, validate_key))
    return 0;

  return 1;
}

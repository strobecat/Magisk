#include "sprd_sign.h"
#include <memory.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

RSA *public_key_from_info(const struct sprd_rsa_info *info) {
  BIGNUM *e = BN_bin2bn((uint8_t *)&info->e, 4, NULL);
  BIGNUM *n = BN_bin2bn(info->n, info->bits >> 3, NULL);
  RSA *key = RSA_new_public_key(n, e);
  BN_free(e);
  BN_free(n);
  return key;
}

int verify_crypted_hash(const struct sprd_crypted_hash *crypted_hash,
                        RSA *public_key) {
  RSA *key;
  if (public_key)
    key = public_key;
  else
    key = public_key_from_info(&crypted_hash->rsa_info);
  size_t key_size = RSA_size(key);
  uint8_t *decrypted = (uint8_t *)malloc(key_size);
  RSA_public_decrypt(key_size, crypted_hash->signature, decrypted, key,
                     RSA_PKCS1_PADDING);
  if (!public_key)
    RSA_free(key);
  int correct =
      memcmp(crypted_hash->hash, decrypted,
             sizeof(crypted_hash->hash) + sizeof(crypted_hash->unknown2) +
                 sizeof(crypted_hash->anti_rollback_version)) == 0;
  free(decrypted);
  return correct;
}

void signature_crypted_hash(struct sprd_crypted_hash *crypted_hash,
                            RSA *private_key) {
  RSA *key;
  if (private_key)
    key = private_key;
  else
    key = get_private_key();

  RSA_private_encrypt(
      sizeof(crypted_hash->hash) + sizeof(crypted_hash->unknown2) +
          sizeof(crypted_hash->anti_rollback_version),
      crypted_hash->hash, crypted_hash->signature, key, RSA_PKCS1_PADDING);
  if (!private_key)
    RSA_free(key);
}

RSA *get_private_key() {
  BIGNUM *n = BN_bin2bn(private_key_n, sizeof(private_key_n), NULL);
  BIGNUM *e = BN_bin2bn(private_key_e, sizeof(private_key_e), NULL);
  BIGNUM *d = BN_bin2bn(private_key_d, sizeof(private_key_d), NULL);
  RSA *key = RSA_new_private_key_no_crt(n, e, d);
  BN_free(n);
  BN_free(e);
  BN_free(d);
  return key;
}

int is_key_supported(const RSA *public_key) {
  const BIGNUM *e = RSA_get0_e(public_key);
  const BIGNUM *n = RSA_get0_n(public_key);
  BIGNUM *expected_e = BN_bin2bn(private_key_e, sizeof(private_key_e), NULL);
  BIGNUM *expected_n = BN_bin2bn(private_key_n, sizeof(private_key_n), NULL);

  int successful = BN_equal_consttime(e, expected_e) == 1;
  successful += BN_equal_consttime(n, expected_n) == 1;

  BN_free(expected_e);
  BN_free(expected_n);

  return successful == 2;
}

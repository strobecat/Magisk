#ifndef SPRD_SIGN_H
#define SPRD_SIGN_H

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ref:
// https://github.com/TomKing062/vendor_sprd_proprietories-source_packimage/tree/main/sign_image/v2/sprd_sign

const uint8_t sprdsign_default_privkey_n[] = {
    220, 228, 193, 79,  71,  245, 211, 159, 23,  152, 65,  225, 130, 22,  149,
    253, 127, 117, 69,  3,   40,  45,  51,  242, 208, 229, 130, 180, 140, 160,
    224, 154, 224, 96,  94,  46,  156, 194, 127, 114, 181, 4,   134, 64,  2,
    126, 254, 103, 164, 242, 63,  162, 232, 233, 205, 148, 226, 170, 145, 206,
    56,  127, 20,  157, 210, 127, 151, 216, 152, 64,  67,  103, 183, 74,  158,
    58,  13,  123, 48,  28,  152, 173, 150, 65,  109, 37,  65,  196, 161, 108,
    250, 137, 166, 83,  151, 224, 158, 172, 55,  53,  42,  0,   48,  54,  137,
    86,  189, 48,  212, 193, 173, 49,  77,  156, 157, 218, 17,  228, 254, 199,
    35,  161, 177, 180, 144, 149, 129, 150, 202, 204, 191, 42,  224, 10,  60,
    86,  151, 12,  140, 156, 75,  244, 49,  181, 6,   177, 73,  187, 21,  113,
    100, 150, 154, 220, 168, 204, 217, 65,  102, 19,  122, 53,  168, 17,  151,
    231, 252, 9,   121, 88,  251, 171, 86,  112, 164, 146, 116, 198, 63,  197,
    164, 41,  136, 84,  144, 226, 223, 6,   181, 215, 38,  11,  58,  100, 187,
    90,  37,  192, 198, 62,  100, 228, 76,  134, 190, 96,  108, 210, 56,  45,
    142, 72,  35,  109, 4,   184, 171, 164, 227, 49,  33,  224, 91,  87,  156,
    177, 160, 118, 150, 183, 239, 135, 38,  26,  196, 211, 25,  58,  33,  56,
    233, 145, 134, 168, 146, 157, 79,  112, 43,  162, 32,  189, 208, 133, 8,
    179};
const uint8_t sprdsign_default_privkey_e[] = {1, 0, 1};
const uint8_t sprdsign_default_privkey_d[] = {
    152, 28,  134, 233, 219, 121, 243, 18,  153, 34,  230, 43,  46,  115, 243,
    49,  175, 181, 199, 162, 86,  230, 89,  225, 153, 236, 146, 71,  86,  151,
    234, 83,  124, 179, 159, 231, 165, 87,  98,  128, 81,  27,  30,  127, 177,
    184, 85,  228, 117, 119, 196, 78,  160, 233, 112, 2,   88,  220, 112, 175,
    123, 196, 55,  36,  63,  50,  82,  20,  123, 51,  181, 183, 20,  71,  52,
    18,  113, 250, 36,  181, 108, 134, 12,  244, 92,  254, 204, 253, 100, 212,
    48,  234, 221, 56,  175, 91,  164, 168, 159, 19,  227, 42,  98,  9,   12,
    38,  72,  253, 249, 100, 173, 169, 71,  242, 211, 216, 185, 125, 225, 220,
    172, 50,  202, 182, 182, 225, 221, 107, 251, 220, 148, 167, 169, 92,  175,
    118, 211, 54,  182, 234, 167, 136, 10,  55,  118, 253, 209, 215, 28,  63,
    30,  38,  116, 128, 99,  129, 47,  246, 46,  79,  54,  255, 80,  12,  5,
    239, 119, 12,  9,   168, 201, 222, 85,  187, 3,   226, 109, 227, 123, 3,
    42,  49,  211, 61,  80,  6,   91,  100, 127, 148, 188, 179, 125, 254, 27,
    112, 113, 119, 130, 56,  124, 25,  239, 253, 153, 208, 191, 189, 36,  255,
    33,  71,  5,   26,  211, 174, 177, 143, 6,   14,  159, 155, 170, 74,  182,
    224, 244, 159, 160, 8,   91,  186, 36,  11,  15,  234, 21,  0,   118, 45,
    50,  160, 190, 121, 220, 14,  165, 124, 23,  36,  32,  172, 104, 93,  54,
    225};

// ref:
// https://github.com/TomKing062/vendor_sprd_proprietories-source_packimage/blob/88046980c972751acfbd787291cf3cc4e8ea02ed/sign_image/v2/sprd_sign/common/verify/inc/sprdsec_header.h

struct sprdsign_rsa_pubkey {
  uint32_t bits;
  uint32_t e;
  uint8_t n[2048 >> 3];
} __attribute__((packed));

struct sprd_content_signature {
  uint32_t signature_type; // 0
  struct sprdsign_rsa_pubkey pubkey;
  uint8_t checksum[SHA256_DIGEST_LENGTH];
  uint32_t type; // usually 0
  uint32_t anti_rollback_version;
  uint8_t signature[2048 >> 3]; // (checksum + type + anti_rollback_version)
                                // signatured by privkey
} __attribute__((packed));

struct sprd_footer {
  uint8_t magic[16]; /* All 0x00 */
  uint64_t payload_size;
  uint64_t payload_offset;
  uint64_t signature_size;
  uint64_t signature_offset;
  // paramaters below shall all be 0x00 for normal SRPD phone
  uint64_t private_size;
  uint64_t private_offset;
  uint64_t dbg_signature_primary_size;
  uint64_t dbg_signature_primary_offset;
  uint64_t dbg_signature_devloper_size;
  uint64_t dbg_signature_devloper_offset;
} __attribute__((packed));

RSA *sprdsign_rsa_deserialize(const struct sprdsign_rsa_pubkey *data);
RSA *sprdsign_get_default_privkey();
int sprdsign_verify_signature(const struct sprd_content_signature *signature,
                              RSA *key);
int sprdsign_sign_signature(struct sprd_content_signature *signature,
                            RSA *private_key);
int sprdsign_check_footer(struct sprd_footer *footer, size_t payload_size,
                          size_t total_size);
int sprdsign_verify(void *image, size_t size, RSA *validate_key);

#ifdef __cplusplus
}
#endif

#endif // SPRD_SIGN_H

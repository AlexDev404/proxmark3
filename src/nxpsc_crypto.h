//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// libnxpsc - crypto primitives used by the NXP smartcard secure channels
//-----------------------------------------------------------------------------

#ifndef NXPSC_CRYPTO_H__
#define NXPSC_CRYPTO_H__

#include "nxpsc/nxpsc.h"

#define NXPSC_AES_BLOCK     16
#define NXPSC_DES_BLOCK     8
#define NXPSC_MAX_BLOCK     16

// LRP, AN12304
#define NXPSC_LRP_PLAINTEXTS    16
#define NXPSC_LRP_UPDATED_KEYS  4
#define NXPSC_LRP_MAX_COUNTER   (NXPSC_AES_BLOCK * 4)

typedef struct {
    uint8_t key[NXPSC_AES_BLOCK];
    bool bit_padding;
    size_t plaintexts_count;
    uint8_t plaintexts[NXPSC_LRP_PLAINTEXTS][NXPSC_AES_BLOCK];
    size_t updated_keys_count;
    uint8_t updated_keys[NXPSC_LRP_UPDATED_KEYS][NXPSC_AES_BLOCK];
    size_t use_updated_key;
    uint8_t counter[NXPSC_LRP_MAX_COUNTER];
    size_t counter_len_nibbles;
} nxpsc_lrp_ctx_t;

size_t nxpsc_block_size(nxpsc_keytype_t type);
bool nxpsc_key_is_valid(const nxpsc_key_t *key);

int nxpsc_random_bytes(uint8_t *out, size_t len);
// deterministic RNG override, used by the self tests and by callers that need
// reproducible sessions. pass NULL to restore the platform RNG
void nxpsc_set_rng(int (*rng)(void *ctx, uint8_t *out, size_t len), void *ctx);

void nxpsc_xor(uint8_t *dst, const uint8_t *src, size_t len);

// raw block ciphers. iv is updated in place, pass NULL for an all zero iv
int nxpsc_cbc_crypt(nxpsc_keytype_t type, const uint8_t *key, uint8_t *iv,
                    const uint8_t *in, size_t len, uint8_t *out, bool encrypt);
// MF3ICD40 silicon can only run the cipher in the encrypt direction, so on the
// D40 secure channel the reader has to chain like CBC but call the decrypt
// primitive. dir_to_send xors the IV before the block operation, encode picks
// the primitive
int nxpsc_cbc_crypt_ex(nxpsc_keytype_t type, const uint8_t *key, uint8_t *iv,
                       const uint8_t *in, size_t len, uint8_t *out,
                       bool dir_to_send, bool encode);
int nxpsc_ecb_encrypt_block(nxpsc_keytype_t type, const uint8_t *key,
                            const uint8_t *in, uint8_t *out);
int nxpsc_ecb_decrypt_block(nxpsc_keytype_t type, const uint8_t *key,
                            const uint8_t *in, uint8_t *out);

// NIST SP 800-38B CMAC over DES/3DES (64 bit block) or AES (128 bit block).
// iv, when not NULL, is used as the starting chaining value and receives the
// resulting mac, which is how the DESFire EV1 secure channel chains its IV.
// min_len pads the message to at least that many bytes before processing
int nxpsc_cmac(nxpsc_keytype_t type, const uint8_t *key, uint8_t *iv,
               const uint8_t *data, size_t len, size_t min_len, uint8_t *mac);
void nxpsc_cmac_subkeys(nxpsc_keytype_t type, const uint8_t *key, uint8_t *sk1, uint8_t *sk2);

// DESFire CRCs. crc32 is the JAMCRC variant, crc16 the ISO 14443-A one
void nxpsc_crc32(const uint8_t *data, size_t len, uint8_t *crc);
void nxpsc_crc16(const uint8_t *data, size_t len, uint8_t *crc);

// (2K3)DES keys carry their version in the LSB of every key byte
void nxpsc_des_key_set_version(uint8_t *key, nxpsc_keytype_t type, uint8_t version);
uint8_t nxpsc_des_key_get_version(const uint8_t *key);

// AN10922. div_input is the diversification data without the padding constant
int nxpsc_kdf_an10922(const nxpsc_key_t *master, const uint8_t *div_input, size_t len,
                      nxpsc_key_t *out);

// session keys
void nxpsc_session_key_d40(const uint8_t *rnda, const uint8_t *rndb, nxpsc_keytype_t type,
                           uint8_t *out);
int nxpsc_session_key_ev2(const uint8_t *key, const uint8_t *rnda, const uint8_t *rndb,
                          bool enc_key, uint8_t *out);
int nxpsc_session_key_lrp(const uint8_t *key, const uint8_t *rnda, const uint8_t *rndb,
                          bool enc_key, uint8_t *out);
// transaction MAC session keys, AN12343 / MF2DLHX0
int nxpsc_trans_session_key_ev2(const uint8_t *key, uint32_t counter, const uint8_t *uid,
                                bool for_mac, uint8_t *out);
int nxpsc_trans_session_key_lrp(const uint8_t *key, uint32_t counter, const uint8_t *uid,
                                bool for_mac, uint8_t *out);

// LRP, AN12304
void nxpsc_lrp_init(nxpsc_lrp_ctx_t *ctx, const uint8_t *key, size_t updated_key,
                    bool bit_padding);
void nxpsc_lrp_set_counter(nxpsc_lrp_ctx_t *ctx, const uint8_t *counter, size_t len_nibbles);
void nxpsc_lrp_eval(nxpsc_lrp_ctx_t *ctx, const uint8_t *iv, size_t iv_len_nibbles, bool final,
                    uint8_t *out);
void nxpsc_lrp_inc_counter(uint8_t *counter, size_t len_nibbles);
int nxpsc_lrp_encode(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len,
                     uint8_t *out, size_t cap, size_t *out_len);
int nxpsc_lrp_decode(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len,
                     uint8_t *out, size_t cap, size_t *out_len);
void nxpsc_lrp_cmac(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len, uint8_t *mac);
// truncated mac, odd bytes of the full mac
void nxpsc_lrp_cmac8(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len, uint8_t *mac);

// odd byte truncation shared by EV2 and LRP macs
void nxpsc_truncate_mac(const uint8_t *mac16, uint8_t *mac8);

#endif // NXPSC_CRYPTO_H__

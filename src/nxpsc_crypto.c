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
// libnxpsc - crypto primitives
//
// cross checked against proxmark3 client/src/mifare/desfirecrypto.c,
// libfreefare mifare_desfire_crypto.c / mifare_key_deriver.c, RevK DESFireAES
// desfireaes.c and waza-ari/python-desfire src/desfire/key.py
//-----------------------------------------------------------------------------

#include "nxpsc_crypto.h"

#include <string.h>
#include <stdlib.h>

#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/platform_util.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <stdio.h>
#endif

//-----------------------------------------------------------------------------
// helpers
//-----------------------------------------------------------------------------
size_t nxpsc_key_size(nxpsc_keytype_t type) {
    switch (type) {
        case NXPSC_KEY_DES:
            return 8;
        case NXPSC_KEY_2K3DES:
        case NXPSC_KEY_AES128:
            return 16;
        case NXPSC_KEY_3K3DES:
            return 24;
        case NXPSC_KEY_AES256:
            return 32;
    }
    return 0;
}

size_t nxpsc_block_size(nxpsc_keytype_t type) {
    switch (type) {
        case NXPSC_KEY_DES:
        case NXPSC_KEY_2K3DES:
        case NXPSC_KEY_3K3DES:
            return NXPSC_DES_BLOCK;
        case NXPSC_KEY_AES128:
        case NXPSC_KEY_AES256:
            return NXPSC_AES_BLOCK;
    }
    return 0;
}

bool nxpsc_key_is_valid(const nxpsc_key_t *key) {
    return (key != NULL && nxpsc_key_size(key->type) != 0);
}

bool nxpsc_memeq(const uint8_t *a, const uint8_t *b, size_t len) {
    if ((len > 0) && (a == NULL || b == NULL)) {
        return false;
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

void nxpsc_secure_zero(void *buf, size_t len) {
    if (len == 0 || buf == NULL) {
        return;
    }
    mbedtls_platform_zeroize(buf, len);
}

void nxpsc_xor(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

void nxpsc_truncate_mac(const uint8_t *mac16, uint8_t *mac8) {
    for (size_t i = 0; i < 8; i++) {
        mac8[i] = mac16[i * 2 + 1];
    }
}

//-----------------------------------------------------------------------------
// random
//-----------------------------------------------------------------------------
static int (*g_rng)(void *ctx, uint8_t *out, size_t len) = NULL;
static void *g_rng_ctx = NULL;

void nxpsc_set_rng(int (*rng)(void *ctx, uint8_t *out, size_t len), void *ctx) {
    g_rng = rng;
    g_rng_ctx = ctx;
}

int nxpsc_random_bytes(uint8_t *out, size_t len) {
    if (out == NULL || len == 0) {
        return NXPSC_E_PARAM;
    }

    if (g_rng != NULL) {
        return g_rng(g_rng_ctx, out, len);
    }

#if defined(_WIN32)
    if (BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return NXPSC_E_CRYPTO;
    }
    return NXPSC_OK;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return NXPSC_E_CRYPTO;
    }

    size_t rlen = fread(out, 1, len, f);
    fclose(f);
    return (rlen == len) ? NXPSC_OK : NXPSC_E_CRYPTO;
#endif
}

//-----------------------------------------------------------------------------
// block ciphers
//-----------------------------------------------------------------------------
// 2K3DES keys with both halves equal behave exactly like single DES, which is
// what a factory DESFire master key looks like after DesfireSetKey()
static int des_setkey(mbedtls_des3_context *ctx3, mbedtls_des_context *ctx1,
                      nxpsc_keytype_t type, const uint8_t *key, bool encrypt) {
    uint8_t k24[24];

    switch (type) {
        case NXPSC_KEY_DES:
            return encrypt ? mbedtls_des_setkey_enc(ctx1, key) : mbedtls_des_setkey_dec(ctx1, key);
        case NXPSC_KEY_2K3DES:
            memcpy(k24, key, 16);
            memcpy(k24 + 16, key, 8);
            {
                int rc = encrypt ? mbedtls_des3_set3key_enc(ctx3, k24) : mbedtls_des3_set3key_dec(ctx3, k24);
                nxpsc_secure_zero(k24, sizeof(k24));
                return rc;
            }
        case NXPSC_KEY_3K3DES:
            return encrypt ? mbedtls_des3_set3key_enc(ctx3, key) : mbedtls_des3_set3key_dec(ctx3, key);
        default:
            nxpsc_secure_zero(k24, sizeof(k24));
            return -1;
    }
}

int nxpsc_ecb_encrypt_block(nxpsc_keytype_t type, const uint8_t *key,
                            const uint8_t *in, uint8_t *out) {
    if (key == NULL || in == NULL || out == NULL) {
        return NXPSC_E_PARAM;
    }

    int rc = NXPSC_E_CRYPTO;

    if (type == NXPSC_KEY_AES128 || type == NXPSC_KEY_AES256) {
        mbedtls_aes_context actx;
        mbedtls_aes_init(&actx);
        if (mbedtls_aes_setkey_enc(&actx, key, (unsigned int)nxpsc_key_size(type) * 8) == 0 &&
                mbedtls_aes_crypt_ecb(&actx, MBEDTLS_AES_ENCRYPT, in, out) == 0) {
            rc = NXPSC_OK;
        }
        mbedtls_aes_free(&actx);
        return rc;
    }

    mbedtls_des_context ctx1;
    mbedtls_des3_context ctx3;
    mbedtls_des_init(&ctx1);
    mbedtls_des3_init(&ctx3);

    if (des_setkey(&ctx3, &ctx1, type, key, true) == 0) {
        if (type == NXPSC_KEY_DES) {
            rc = (mbedtls_des_crypt_ecb(&ctx1, in, out) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO;
        } else {
            rc = (mbedtls_des3_crypt_ecb(&ctx3, in, out) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO;
        }
    }

    mbedtls_des_free(&ctx1);
    mbedtls_des3_free(&ctx3);
    return rc;
}

int nxpsc_ecb_decrypt_block(nxpsc_keytype_t type, const uint8_t *key,
                            const uint8_t *in, uint8_t *out) {
    if (key == NULL || in == NULL || out == NULL) {
        return NXPSC_E_PARAM;
    }

    int rc = NXPSC_E_CRYPTO;

    if (type == NXPSC_KEY_AES128 || type == NXPSC_KEY_AES256) {
        mbedtls_aes_context actx;
        mbedtls_aes_init(&actx);
        if (mbedtls_aes_setkey_dec(&actx, key, (unsigned int)nxpsc_key_size(type) * 8) == 0 &&
                mbedtls_aes_crypt_ecb(&actx, MBEDTLS_AES_DECRYPT, in, out) == 0) {
            rc = NXPSC_OK;
        }
        mbedtls_aes_free(&actx);
        return rc;
    }

    mbedtls_des_context ctx1;
    mbedtls_des3_context ctx3;
    mbedtls_des_init(&ctx1);
    mbedtls_des3_init(&ctx3);

    if (des_setkey(&ctx3, &ctx1, type, key, false) == 0) {
        if (type == NXPSC_KEY_DES) {
            rc = (mbedtls_des_crypt_ecb(&ctx1, in, out) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO;
        } else {
            rc = (mbedtls_des3_crypt_ecb(&ctx3, in, out) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO;
        }
    }

    mbedtls_des_free(&ctx1);
    mbedtls_des3_free(&ctx3);
    return rc;
}

int nxpsc_cbc_crypt_ex(nxpsc_keytype_t type, const uint8_t *key, uint8_t *iv,
                       const uint8_t *in, size_t len, uint8_t *out,
                       bool dir_to_send, bool encode) {
    size_t bs = nxpsc_block_size(type);

    if (key == NULL || in == NULL || out == NULL || bs == 0) {
        return NXPSC_E_PARAM;
    }

    if (len == 0 || (len % bs) != 0) {
        return NXPSC_E_LENGTH;
    }

    uint8_t civ[NXPSC_MAX_BLOCK] = {0};
    if (iv != NULL) {
        memcpy(civ, iv, bs);
    }

    uint8_t src[NXPSC_MAX_BLOCK];
    uint8_t dst[NXPSC_MAX_BLOCK];

    for (size_t off = 0; off < len; off += bs) {
        // in and out may alias, keep a copy of the input block
        memcpy(src, in + off, bs);

        uint8_t block[NXPSC_MAX_BLOCK];
        memcpy(block, src, bs);
        if (dir_to_send) {
            nxpsc_xor(block, civ, bs);
        }

        int rc = encode ? nxpsc_ecb_encrypt_block(type, key, block, dst)
                 : nxpsc_ecb_decrypt_block(type, key, block, dst);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (dir_to_send) {
            memcpy(civ, dst, bs);
        } else {
            nxpsc_xor(dst, civ, bs);
            memcpy(civ, src, bs);
        }

        memcpy(out + off, dst, bs);
    }

    if (iv != NULL) {
        memcpy(iv, civ, bs);
    }
    return NXPSC_OK;
}

int nxpsc_cbc_crypt(nxpsc_keytype_t type, const uint8_t *key, uint8_t *iv,
                    const uint8_t *in, size_t len, uint8_t *out, bool encrypt) {
    return nxpsc_cbc_crypt_ex(type, key, iv, in, len, out, encrypt, encrypt);
}

//-----------------------------------------------------------------------------
// CMAC, NIST SP 800-38B
//-----------------------------------------------------------------------------
static void shift_left(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len - 1; i++) {
        data[i] = (uint8_t)((data[i] << 1) | (data[i + 1] >> 7));
    }
    data[len - 1] <<= 1;
}

void nxpsc_cmac_subkeys(nxpsc_keytype_t type, const uint8_t *key, uint8_t *sk1, uint8_t *sk2) {
    size_t bs = nxpsc_block_size(type);
    if (bs == 0) {
        return;
    }

    const uint8_t R = (bs == NXPSC_DES_BLOCK) ? 0x1B : 0x87;
    uint8_t l[NXPSC_MAX_BLOCK] = {0};
    uint8_t iv[NXPSC_MAX_BLOCK] = {0};

    if (nxpsc_cbc_crypt(type, key, iv, l, bs, l, true) != NXPSC_OK) {
        return;
    }

    memcpy(sk1, l, bs);
    bool xor1 = (l[0] & 0x80) != 0;
    shift_left(sk1, bs);
    if (xor1) {
        sk1[bs - 1] ^= R;
    }

    memcpy(sk2, sk1, bs);
    bool xor2 = (sk1[0] & 0x80) != 0;
    shift_left(sk2, bs);
    if (xor2) {
        sk2[bs - 1] ^= R;
    }
}

int nxpsc_cmac(nxpsc_keytype_t type, const uint8_t *key, uint8_t *iv,
               const uint8_t *data, size_t len, size_t min_len, uint8_t *mac) {
    size_t bs = nxpsc_block_size(type);
    if (key == NULL || bs == 0 || (len > 0 && data == NULL)) {
        return NXPSC_E_PARAM;
    }

    size_t want = (min_len > len) ? min_len : len;
    // room for the 0x80 padding byte
    size_t buflen = ((want + 1 + bs - 1) / bs) * bs;
    if (buflen == 0) {
        buflen = bs;
    }

    uint8_t *buffer = calloc(buflen, 1);
    if (buffer == NULL) {
        return NXPSC_E_MEMORY;
    }

    uint8_t sk1[NXPSC_MAX_BLOCK] = {0};
    uint8_t sk2[NXPSC_MAX_BLOCK] = {0};
    nxpsc_cmac_subkeys(type, key, sk1, sk2);

    if (len > 0) {
        memcpy(buffer, data, len);
    }

    size_t mlen = len;
    if (mlen == 0 || (mlen % bs) != 0 || mlen < min_len) {
        buffer[mlen++] = 0x80;
        while ((mlen % bs) != 0 || mlen < min_len) {
            buffer[mlen++] = 0x00;
        }
        nxpsc_xor(buffer + mlen - bs, sk2, bs);
    } else {
        nxpsc_xor(buffer + mlen - bs, sk1, bs);
    }

    uint8_t localiv[NXPSC_MAX_BLOCK] = {0};
    uint8_t *useiv = (iv != NULL) ? iv : localiv;

    int rc = nxpsc_cbc_crypt(type, key, useiv, buffer, mlen, buffer, true);
    if (rc == NXPSC_OK && mac != NULL) {
        memcpy(mac, useiv, bs);
    }

    nxpsc_secure_zero(buffer, buflen);
    free(buffer);
    return rc;
}

//-----------------------------------------------------------------------------
// CRC
//-----------------------------------------------------------------------------
void nxpsc_crc32(const uint8_t *data, size_t len, uint8_t *crc) {
    uint32_t c = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        c ^= data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t out = c & 1;
            c >>= 1;
            if (out) {
                c ^= 0xEDB88320;
            }
        }
    }

    crc[0] = (uint8_t)(c & 0xFF);
    crc[1] = (uint8_t)((c >> 8) & 0xFF);
    crc[2] = (uint8_t)((c >> 16) & 0xFF);
    crc[3] = (uint8_t)((c >> 24) & 0xFF);
}

void nxpsc_crc16(const uint8_t *data, size_t len, uint8_t *crc) {
    uint16_t c = 0x6363;

    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i] ^ (uint8_t)(c & 0xFF);
        b ^= (uint8_t)(b << 4);
        c = (uint16_t)((c >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4));
    }

    crc[0] = (uint8_t)(c & 0xFF);
    crc[1] = (uint8_t)((c >> 8) & 0xFF);
}

//-----------------------------------------------------------------------------
// key versions
//-----------------------------------------------------------------------------
void nxpsc_des_key_set_version(uint8_t *key, nxpsc_keytype_t type, uint8_t version) {
    if (type != NXPSC_KEY_DES && type != NXPSC_KEY_2K3DES && type != NXPSC_KEY_3K3DES) {
        return;
    }

    size_t klen = nxpsc_key_size(type);
    for (size_t n = 0; n < 8; n++) {
        uint8_t bit = (version & (1 << (7 - n))) ? 1 : 0;
        for (size_t k = n; k < klen; k += 8) {
            key[k] = (uint8_t)((key[k] & 0xFE) | bit);
        }
    }
}

uint8_t nxpsc_des_key_get_version(const uint8_t *key) {
    uint8_t version = 0;

    for (size_t n = 0; n < 8; n++) {
        version |= (uint8_t)((key[n] & 1) << (7 - n));
    }
    return version;
}

//-----------------------------------------------------------------------------
// AN10922 key diversification
//-----------------------------------------------------------------------------
static int kdf_block(const nxpsc_key_t *master, uint8_t constant, const uint8_t *div_input,
                     size_t len, size_t min_len, uint8_t *out) {
    uint8_t buffer[64] = {0};

    buffer[0] = constant;
    memcpy(buffer + 1, div_input, len);

    uint8_t mac[NXPSC_MAX_BLOCK] = {0};
    uint8_t iv[NXPSC_MAX_BLOCK] = {0};

    int rc = nxpsc_cmac(master->type, master->data, iv, buffer, len + 1, min_len, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }

    memcpy(out, mac, nxpsc_block_size(master->type));
    return NXPSC_OK;
}

int nxpsc_kdf_an10922(const nxpsc_key_t *master, const uint8_t *div_input, size_t len,
                      nxpsc_key_t *out) {
    if (!nxpsc_key_is_valid(master) || div_input == NULL || out == NULL) {
        return NXPSC_E_PARAM;
    }

    if (len < 1 || len > 31) {
        return NXPSC_E_LENGTH;
    }

    size_t bs = nxpsc_block_size(master->type);
    size_t min_len = bs * 2;
    int rc;

    memset(out, 0, sizeof(*out));
    out->type = master->type;

    switch (master->type) {
        case NXPSC_KEY_AES128:
            rc = kdf_block(master, 0x01, div_input, len, min_len, out->data);
            break;

        case NXPSC_KEY_AES256:
            // AN10922 itself only specifies AES128 and AES192. the 256 bit
            // variant below follows the same two round scheme, none of the
            // reference libraries implement it, so verify against your card
            rc = kdf_block(master, 0x41, div_input, len, min_len, out->data);
            if (rc == NXPSC_OK) {
                rc = kdf_block(master, 0x42, div_input, len, min_len, out->data + bs);
            }
            break;

        case NXPSC_KEY_2K3DES:
            rc = kdf_block(master, 0x21, div_input, len, min_len, out->data);
            if (rc == NXPSC_OK) {
                rc = kdf_block(master, 0x22, div_input, len, min_len, out->data + bs);
            }
            break;

        case NXPSC_KEY_3K3DES:
            rc = kdf_block(master, 0x31, div_input, len, min_len, out->data);
            if (rc == NXPSC_OK) {
                rc = kdf_block(master, 0x32, div_input, len, min_len, out->data + bs);
            }
            if (rc == NXPSC_OK) {
                rc = kdf_block(master, 0x33, div_input, len, min_len, out->data + bs * 2);
            }
            break;

        default:
            // AN10922 does not define a derivation for single DES
            return NXPSC_E_UNSUPPORTED;
    }

    // the key version is not part of the derivation, the caller sets it when
    // the derived key is written to a card
    out->version = master->version;
    return rc;
}

//-----------------------------------------------------------------------------
// session keys
//-----------------------------------------------------------------------------
void nxpsc_session_key_d40(const uint8_t *rnda, const uint8_t *rndb, nxpsc_keytype_t type,
                           uint8_t *out) {
    switch (type) {
        case NXPSC_KEY_DES:
            memcpy(out, rnda, 4);
            memcpy(out + 4, rndb, 4);
            break;

        case NXPSC_KEY_2K3DES:
            memcpy(out, rnda, 4);
            memcpy(out + 4, rndb, 4);
            memcpy(out + 8, rnda + 4, 4);
            memcpy(out + 12, rndb + 4, 4);
            break;

        case NXPSC_KEY_3K3DES:
            memcpy(out, rnda, 4);
            memcpy(out + 4, rndb, 4);
            memcpy(out + 8, rnda + 6, 4);
            memcpy(out + 12, rndb + 6, 4);
            memcpy(out + 16, rnda + 12, 4);
            memcpy(out + 20, rndb + 12, 4);
            break;

        case NXPSC_KEY_AES128:
        case NXPSC_KEY_AES256:
            memcpy(out, rnda, 4);
            memcpy(out + 4, rndb, 4);
            memcpy(out + 8, rnda + 12, 4);
            memcpy(out + 12, rndb + 12, 4);
            break;
    }
}

// AN12343, session vector SV1 / SV2
int nxpsc_session_key_ev2(const uint8_t *key, const uint8_t *rnda, const uint8_t *rndb,
                          bool enc_key, uint8_t *out) {
    uint8_t data[32] = {0};

    if (enc_key) {
        data[0] = 0xA5;
        data[1] = 0x5A;
    } else {
        data[0] = 0x5A;
        data[1] = 0xA5;
    }
    data[3] = 0x01;
    data[5] = 0x80;

    memcpy(data + 6, rnda, 8);
    nxpsc_xor(data + 8, rndb, 6);
    memcpy(data + 14, rndb + 6, 10);
    memcpy(data + 24, rnda + 8, 8);

    uint8_t iv[NXPSC_AES_BLOCK] = {0};
    return nxpsc_cmac(NXPSC_KEY_AES128, key, iv, data, sizeof(data), 0, out);
}

// MF2DLHX0, LRP session vector
int nxpsc_session_key_lrp(const uint8_t *key, const uint8_t *rnda, const uint8_t *rndb,
                          bool enc_key, uint8_t *out) {
    uint8_t data[32] = {0};

    data[1] = 0x01;
    data[3] = 0x80;
    memcpy(data + 4, rnda, 8);
    nxpsc_xor(data + 6, rndb, 6);
    memcpy(data + 12, rndb + 6, 10);
    memcpy(data + 22, rnda + 8, 8);
    data[30] = 0x96;
    data[31] = 0x69;

    // LRP derives both session keys from the same vector, the enc key is the
    // second updated key of the resulting context
    (void)enc_key;

    nxpsc_lrp_ctx_t ctx;
    nxpsc_lrp_init(&ctx, key, 0, true);
    nxpsc_lrp_cmac(&ctx, data, sizeof(data), out);
    nxpsc_secure_zero(&ctx, sizeof(ctx));
    return NXPSC_OK;
}

int nxpsc_trans_session_key_ev2(const uint8_t *key, uint32_t counter, const uint8_t *uid,
                                bool for_mac, uint8_t *out) {
    uint8_t sv[NXPSC_AES_BLOCK] = {0};

    sv[0] = for_mac ? 0x5A : 0xA5;
    sv[2] = 0x01;
    sv[4] = 0x80;

    uint32_t c = counter + 1;
    sv[5] = (uint8_t)(c & 0xFF);
    sv[6] = (uint8_t)((c >> 8) & 0xFF);
    sv[7] = (uint8_t)((c >> 16) & 0xFF);
    sv[8] = (uint8_t)((c >> 24) & 0xFF);
    memcpy(sv + 9, uid, 7);

    uint8_t iv[NXPSC_AES_BLOCK] = {0};
    return nxpsc_cmac(NXPSC_KEY_AES128, key, iv, sv, sizeof(sv), 0, out);
}

int nxpsc_trans_session_key_lrp(const uint8_t *key, uint32_t counter, const uint8_t *uid,
                                bool for_mac, uint8_t *out) {
    uint8_t sv[NXPSC_AES_BLOCK] = {0};

    sv[1] = 0x01;
    sv[3] = 0x80;

    // CommitReaderID is assumed to be the first command of the transaction
    uint32_t c = (counter & 0xFFFF) + 0x00010001;
    sv[4] = (uint8_t)(c & 0xFF);
    sv[5] = (uint8_t)((c >> 8) & 0xFF);
    sv[6] = (uint8_t)((c >> 16) & 0xFF);
    sv[7] = (uint8_t)((c >> 24) & 0xFF);
    memcpy(sv + 8, uid, 7);
    sv[15] = for_mac ? 0x5A : 0xA5;

    nxpsc_lrp_ctx_t ctx;
    nxpsc_lrp_init(&ctx, key, 0, false);
    nxpsc_lrp_cmac(&ctx, sv, sizeof(sv), out);
    nxpsc_secure_zero(&ctx, sizeof(ctx));
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// LRP, AN12304
//-----------------------------------------------------------------------------
static const uint8_t lrp_const_aa[NXPSC_AES_BLOCK] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
};
static const uint8_t lrp_const_55[NXPSC_AES_BLOCK] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};
static const uint8_t lrp_const_00[NXPSC_AES_BLOCK] = {0};

// algorithm 1 and 2
static void lrp_generate_tables(nxpsc_lrp_ctx_t *ctx) {
    uint8_t h[NXPSC_AES_BLOCK];

    memcpy(h, ctx->key, NXPSC_AES_BLOCK);
    for (size_t i = 0; i < NXPSC_LRP_PLAINTEXTS; i++) {
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, h, lrp_const_55, h);
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, h, lrp_const_aa, ctx->plaintexts[i]);
    }
    ctx->plaintexts_count = NXPSC_LRP_PLAINTEXTS;

    nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, ctx->key, lrp_const_aa, h);
    for (size_t i = 0; i < NXPSC_LRP_UPDATED_KEYS; i++) {
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, h, lrp_const_aa, ctx->updated_keys[i]);
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, h, lrp_const_55, h);
    }
    ctx->updated_keys_count = NXPSC_LRP_UPDATED_KEYS;
}

void nxpsc_lrp_init(nxpsc_lrp_ctx_t *ctx, const uint8_t *key, size_t updated_key,
                    bool bit_padding) {
    nxpsc_secure_zero(ctx, sizeof(*ctx));
    memcpy(ctx->key, key, NXPSC_AES_BLOCK);

    lrp_generate_tables(ctx);

    ctx->use_updated_key = updated_key;
    ctx->bit_padding = bit_padding;
    ctx->counter_len_nibbles = NXPSC_AES_BLOCK;
}

void nxpsc_lrp_set_counter(nxpsc_lrp_ctx_t *ctx, const uint8_t *counter, size_t len_nibbles) {
    if (len_nibbles / 2 > NXPSC_LRP_MAX_COUNTER) {
        return;
    }
    memset(ctx->counter, 0, sizeof(ctx->counter));
    memcpy(ctx->counter, counter, (len_nibbles + 1) / 2);
    ctx->counter_len_nibbles = len_nibbles;
}

// algorithm 3
void nxpsc_lrp_eval(nxpsc_lrp_ctx_t *ctx, const uint8_t *iv, size_t iv_len_nibbles, bool final,
                    uint8_t *out) {
    uint8_t ry[NXPSC_AES_BLOCK];
    memcpy(ry, ctx->updated_keys[ctx->use_updated_key], NXPSC_AES_BLOCK);

    for (size_t i = 0; i < iv_len_nibbles; i++) {
        uint8_t nibble = (i % 2) ? (iv[i / 2] & 0x0F) : ((iv[i / 2] >> 4) & 0x0F);
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, ry, ctx->plaintexts[nibble], ry);
    }

    if (final) {
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, ry, lrp_const_00, ry);
    }
    memcpy(out, ry, NXPSC_AES_BLOCK);
}

void nxpsc_lrp_inc_counter(uint8_t *counter, size_t len_nibbles) {
    bool carry = true;

    for (int i = (int)len_nibbles - 1; i >= 0; i--) {
        uint8_t nibble = (i % 2) ? (counter[i / 2] & 0x0F) : ((counter[i / 2] >> 4) & 0x0F);

        if (carry) {
            nibble++;
        }
        carry = (nibble > 0x0F);

        if (i % 2) {
            counter[i / 2] = (uint8_t)((counter[i / 2] & 0xF0) | (nibble & 0x0F));
        } else {
            counter[i / 2] = (uint8_t)((counter[i / 2] & 0x0F) | ((nibble << 4) & 0xF0));
        }

        if (carry == false) {
            break;
        }
    }
}

// algorithm 4
int nxpsc_lrp_encode(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len,
                     uint8_t *out, size_t cap, size_t *out_len) {
    *out_len = 0;

    if (len > 0 && data == NULL) {
        return NXPSC_E_PARAM;
    }

    size_t dlen = len + (ctx->bit_padding ? 1 : 0);
    if ((dlen % NXPSC_AES_BLOCK) != 0) {
        dlen = dlen + NXPSC_AES_BLOCK - (dlen % NXPSC_AES_BLOCK);
    }

    if (dlen == 0) {
        return NXPSC_OK;
    }

    if (dlen > cap) {
        return NXPSC_E_LENGTH;
    }

    uint8_t *buf = calloc(dlen, 1);
    if (buf == NULL) {
        return NXPSC_E_MEMORY;
    }

    if (len > 0) {
        memcpy(buf, data, len);
    }
    if (ctx->bit_padding) {
        buf[len] = 0x80;
    }

    uint8_t y[NXPSC_AES_BLOCK];
    for (size_t off = 0; off < dlen; off += NXPSC_AES_BLOCK) {
        nxpsc_lrp_eval(ctx, ctx->counter, ctx->counter_len_nibbles, true, y);
        nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, y, buf + off, out + off);
        nxpsc_lrp_inc_counter(ctx->counter, ctx->counter_len_nibbles);
    }
    *out_len = dlen;

    nxpsc_secure_zero(buf, dlen);
    free(buf);
    return NXPSC_OK;
}

// algorithm 5
int nxpsc_lrp_decode(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len,
                     uint8_t *out, size_t cap, size_t *out_len) {
    *out_len = 0;

    if (len == 0 || (len % NXPSC_AES_BLOCK) != 0) {
        return NXPSC_E_LENGTH;
    }
    if (len > cap) {
        return NXPSC_E_LENGTH;
    }

    uint8_t y[NXPSC_AES_BLOCK];
    for (size_t off = 0; off < len; off += NXPSC_AES_BLOCK) {
        nxpsc_lrp_eval(ctx, ctx->counter, ctx->counter_len_nibbles, true, y);
        nxpsc_ecb_decrypt_block(NXPSC_KEY_AES128, y, data + off, out + off);
        nxpsc_lrp_inc_counter(ctx->counter, ctx->counter_len_nibbles);
    }
    *out_len = len;

    if (ctx->bit_padding) {
        for (int i = (int)*out_len - 1; i >= (int)(*out_len - NXPSC_AES_BLOCK); i--) {
            if (out[i] == 0x80) {
                *out_len = (size_t)i;
            }
            if (out[i] != 0x00) {
                break;
            }
        }
    }
    return NXPSC_OK;
}

// GF(2^128), x^128 + x^7 + x^2 + x + 1
static void lrp_mul_poly_x(uint8_t *data) {
    bool carry = (data[0] & 0x80) != 0;
    shift_left(data, NXPSC_AES_BLOCK);
    if (carry) {
        data[NXPSC_AES_BLOCK - 1] ^= 0x87;
    }
}

static void lrp_subkeys(const uint8_t *key, uint8_t *sk1, uint8_t *sk2) {
    nxpsc_lrp_ctx_t ctx;
    nxpsc_lrp_init(&ctx, key, 0, true);

    uint8_t y[NXPSC_AES_BLOCK];
    nxpsc_lrp_eval(&ctx, lrp_const_00, NXPSC_AES_BLOCK * 2, true, y);

    lrp_mul_poly_x(y);
    memcpy(sk1, y, NXPSC_AES_BLOCK);

    lrp_mul_poly_x(y);
    memcpy(sk2, y, NXPSC_AES_BLOCK);
}

// algorithm 6
void nxpsc_lrp_cmac(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len, uint8_t *mac) {
    uint8_t sk1[NXPSC_AES_BLOCK] = {0};
    uint8_t sk2[NXPSC_AES_BLOCK] = {0};
    lrp_subkeys(ctx->key, sk1, sk2);

    uint8_t y[NXPSC_AES_BLOCK] = {0};
    size_t done = 0;

    while (len - done > NXPSC_AES_BLOCK) {
        nxpsc_xor(y, data + done, NXPSC_AES_BLOCK);
        nxpsc_lrp_eval(ctx, y, NXPSC_AES_BLOCK * 2, true, y);
        done += NXPSC_AES_BLOCK;
    }

    size_t last = len - done;
    uint8_t bl[NXPSC_AES_BLOCK] = {0};
    if (last > 0) {
        memcpy(bl, data + done, last);
    }

    if (last == NXPSC_AES_BLOCK) {
        nxpsc_xor(y, bl, NXPSC_AES_BLOCK);
        nxpsc_xor(y, sk1, NXPSC_AES_BLOCK);
    } else {
        bl[last] = 0x80;
        nxpsc_xor(y, bl, NXPSC_AES_BLOCK);
        nxpsc_xor(y, sk2, NXPSC_AES_BLOCK);
    }

    nxpsc_lrp_eval(ctx, y, NXPSC_AES_BLOCK * 2, true, mac);
}

void nxpsc_lrp_cmac8(nxpsc_lrp_ctx_t *ctx, const uint8_t *data, size_t len, uint8_t *mac) {
    uint8_t full[NXPSC_AES_BLOCK] = {0};

    nxpsc_lrp_cmac(ctx, data, len, full);
    nxpsc_truncate_mac(full, mac);
}

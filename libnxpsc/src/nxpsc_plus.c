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
// libnxpsc - MIFARE Plus EV1 / EV2 security level 3
//-----------------------------------------------------------------------------

#include "nxpsc_internal.h"

#include <string.h>

#define MFP_BLOCK_SIZE  16

typedef enum {
    MAC_READ_CMD = 0,
    MAC_READ_RESP,
    MAC_WRITE_CMD,
    MAC_WRITE_RESP,
} plus_mac_t;

static int plus_transceive(nxpsc_card_t *card, const uint8_t *tx, size_t tx_len,
                           uint8_t *rx, size_t cap, size_t *rx_len) {
    if (card->transport.transceive == NULL) {
        return NXPSC_E_TRANSPORT;
    }

    int rc = card->transport.transceive(card->transport.ctx, tx, tx_len, rx, cap, rx_len);
    if (rc != 0) {
        return NXPSC_E_TRANSPORT;
    }
    if (*rx_len < 1) {
        return NXPSC_E_LENGTH;
    }

    card->last_status = rx[0];
    if (rx[0] != 0x90) {
        return NXPSC_E_CARD;
    }
    return NXPSC_OK;
}

// AN10922 style MAC over Cmd || Ctr || TI || payload, truncated to 8 bytes
static int plus_mac(nxpsc_card_t *card, plus_mac_t type, uint16_t block, uint8_t count,
                    const uint8_t *data, size_t len, uint8_t *mac) {
    if (card->authenticated == false || len < 1) {
        return NXPSC_E_AUTH;
    }

    uint16_t ctr = card->plus_r_ctr;
    if (type == MAC_WRITE_CMD || type == MAC_WRITE_RESP) {
        ctr = card->plus_w_ctr;
    }

    uint8_t buf[NXPSC_MAX_RESPONSE + 16] = {0};
    size_t buf_len = 0;

    buf[0] = data[0];
    buf[1] = (uint8_t)(ctr & 0xFF);
    buf[2] = (uint8_t)((ctr >> 8) & 0xFF);
    memcpy(buf + 3, card->ti, 4);

    switch (type) {
        case MAC_READ_CMD:
        case MAC_WRITE_CMD:
            if (len - 1 > sizeof(buf) - 7) {
                return NXPSC_E_LENGTH;
            }
            memcpy(buf + 7, data + 1, len - 1);
            buf_len = len + 6;
            break;

        case MAC_READ_RESP:
            if (len - 1 > sizeof(buf) - 10) {
                return NXPSC_E_LENGTH;
            }
            buf[7] = (uint8_t)(block & 0xFF);
            buf[8] = (uint8_t)((block >> 8) & 0xFF);
            buf[9] = count;
            memcpy(buf + 10, data + 1, len - 1);
            buf_len = len + 9;
            break;

        case MAC_WRITE_RESP:
            buf_len = 7;
            break;
    }

    uint8_t full[16] = {0};
    nxpsc_keytype_t type_aes = NXPSC_KEY_AES128;

    int rc = nxpsc_cmac(type_aes, card->session_mac, NULL, buf, buf_len, 0, full);
    if (rc != NXPSC_OK) {
        return rc;
    }

    nxpsc_truncate_mac(full, mac);
    return NXPSC_OK;
}

// data encryption IV, the counters are interleaved differently per direction
static void plus_data_iv(const nxpsc_card_t *card, bool read, uint8_t *iv) {
    memset(iv, 0, MFP_BLOCK_SIZE);

    if (read) {
        uint8_t ctr = (uint8_t)(card->plus_r_ctr & 0xFF);
        for (int i = 0; i < 9; i += 4) {
            iv[i] = ctr;
        }
        memcpy(iv + 12, card->ti, 4);
    } else {
        uint8_t ctr = (uint8_t)(card->plus_w_ctr & 0xFF);
        for (int i = 3; i < MFP_BLOCK_SIZE; i += 4) {
            iv[i] = ctr;
        }
        memcpy(iv, card->ti, 4);
    }
}

int nxpsc_plus_authenticate(nxpsc_card_t *card, uint16_t key_block, const nxpsc_key_t *key,
                            bool first) {
    if (card == NULL || nxpsc_key_is_valid(key) == false) {
        return NXPSC_E_PARAM;
    }
    if (key->type != NXPSC_KEY_AES128) {
        return NXPSC_E_UNSUPPORTED;
    }

    uint8_t cmd[6] = {0};
    size_t cmd_len = 0;

    cmd[cmd_len++] = first ? MFP_AUTH_FIRST : MFP_AUTH_NONFIRST;
    cmd[cmd_len++] = (uint8_t)(key_block & 0xFF);
    cmd[cmd_len++] = (uint8_t)((key_block >> 8) & 0xFF);
    if (first) {
        // length of the PCD capabilities that follow, none here
        cmd[cmd_len++] = 0x00;
    }

    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    if (first) {
        nxpsc_reset_channel(card);
    }

    int rc = plus_transceive(card, cmd, cmd_len, resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 17) {
        return NXPSC_E_LENGTH;
    }

    uint8_t iv_read[MFP_BLOCK_SIZE] = {0};
    uint8_t iv_write[MFP_BLOCK_SIZE] = {0};

    if (first == false) {
        // the non first authentication runs under the session counters
        plus_data_iv(card, true, iv_read);
        plus_data_iv(card, false, iv_write);
    }

    uint8_t rnd_b[17] = {0};
    uint8_t iv[MFP_BLOCK_SIZE] = {0};

    memcpy(iv, iv_read, sizeof(iv));
    rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, key->data, iv, resp + 1, 16, rnd_b, false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    rnd_b[16] = rnd_b[0];

    uint8_t rnd_a[16] = {0};
    rc = nxpsc_random_bytes(rnd_a, sizeof(rnd_a));
    if (rc != NXPSC_OK) {
        return rc;
    }

    uint8_t plain[32] = {0};
    memcpy(plain, rnd_a, 16);
    memcpy(plain + 16, rnd_b + 1, 16);

    uint8_t cmd2[33] = {0};
    cmd2[0] = DF_ADDITIONAL_FRAME;

    memcpy(iv, iv_write, sizeof(iv));
    rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, key->data, iv, plain, sizeof(plain), cmd2 + 1, true);
    if (rc != NXPSC_OK) {
        return rc;
    }

    resp_len = 0;
    rc = plus_transceive(card, cmd2, sizeof(cmd2), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 17) {
        return NXPSC_E_LENGTH;
    }

    uint8_t raw[32] = {0};
    memcpy(iv, iv_read, sizeof(iv));
    rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, key->data, iv, resp + 1,
                         (resp_len - 1 >= 32) ? 32 : 16, raw, false);
    if (rc != NXPSC_OK) {
        return rc;
    }

    // Kenc and Kmac, MF1P(H)x1 data sheet section 9.3
    uint8_t sv[16] = {0};

    memcpy(sv, rnd_a + 11, 5);
    memcpy(sv + 5, rnd_b + 11, 5);
    for (int i = 0; i < 5; i++) {
        sv[10 + i] = rnd_a[4 + i] ^ rnd_b[4 + i];
    }
    sv[15] = 0x11;
    rc = nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, key->data, sv, card->session_enc);
    if (rc != NXPSC_OK) {
        return rc;
    }

    memcpy(sv, rnd_a + 7, 5);
    memcpy(sv + 5, rnd_b + 7, 5);
    for (int i = 0; i < 5; i++) {
        sv[10 + i] = rnd_a[i] ^ rnd_b[i];
    }
    sv[15] = 0x22;
    rc = nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, key->data, sv, card->session_mac);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (first) {
        // first authentication returns TI || PICCcap2 || PCDcap2
        memcpy(card->ti, raw, 4);
        card->plus_r_ctr = 0;
        card->plus_w_ctr = 0;
    }

    memcpy(card->key, key->data, 16);
    card->key_type = NXPSC_KEY_AES128;
    card->key_no = (uint8_t)(key_block & 0xFF);
    card->channel = NXPSC_CHAN_EV2;
    card->authenticated = true;
    return NXPSC_OK;
}

int nxpsc_plus_read(nxpsc_card_t *card, uint16_t block, uint8_t count, bool encrypted,
                    bool maced, uint8_t *out, size_t cap, size_t *out_len) {
    if (card == NULL || out == NULL || out_len == NULL || count == 0) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }
    if ((size_t)count * MFP_BLOCK_SIZE > cap) {
        return NXPSC_E_LENGTH;
    }

    // base opcode 0x31, bit 0 clears the response MAC, bit 1 disables encryption
    uint8_t opcode = 0x31;
    if (maced == false) {
        opcode ^= 0x01;
    }
    if (encrypted == false) {
        opcode ^= 0x02;
    }

    uint8_t cmd[12] = {opcode, (uint8_t)(block & 0xFF), (uint8_t)((block >> 8) & 0xFF), count};
    uint8_t mac[8] = {0};

    int rc = plus_mac(card, MAC_READ_CMD, block, count, cmd, 4, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }
    memcpy(cmd + 4, mac, sizeof(mac));

    uint8_t resp[NXPSC_MAX_RESPONSE] = {0};
    size_t resp_len = 0;

    rc = plus_transceive(card, cmd, sizeof(cmd), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    size_t payload = (size_t)count * MFP_BLOCK_SIZE;
    if (resp_len < payload + 1) {
        return NXPSC_E_LENGTH;
    }

    if (encrypted) {
        uint8_t iv[MFP_BLOCK_SIZE] = {0};
        plus_data_iv(card, true, iv);
        rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, card->session_enc, iv, resp + 1, payload,
                             out, false);
        if (rc != NXPSC_OK) {
            return rc;
        }
    } else {
        memcpy(out, resp + 1, payload);
    }

    if (maced && resp_len >= payload + 9) {
        uint8_t expected[8] = {0};
        rc = plus_mac(card, MAC_READ_RESP, block, count, resp, payload + 1, expected);
        if (rc != NXPSC_OK) {
            return rc;
        }
        card->mac_mismatch = (memcmp(expected, resp + 1 + payload, 8) != 0);
    }

    card->plus_r_ctr++;
    *out_len = payload;

    if (card->mac_mismatch) {
        return NXPSC_E_CRYPTO;
    }
    return NXPSC_OK;
}

static int plus_write_block(nxpsc_card_t *card, uint8_t opcode, uint16_t block,
                            const uint8_t *data, size_t len, bool encrypted) {
    if (card == NULL || data == NULL || len != MFP_BLOCK_SIZE) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    uint8_t cmd[1 + 2 + MFP_BLOCK_SIZE + 8] = {0};
    cmd[0] = opcode;
    cmd[1] = (uint8_t)(block & 0xFF);
    cmd[2] = (uint8_t)((block >> 8) & 0xFF);

    if (encrypted) {
        uint8_t iv[MFP_BLOCK_SIZE] = {0};
        plus_data_iv(card, false, iv);
        int rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, card->session_enc, iv, data,
                                 MFP_BLOCK_SIZE, cmd + 3, true);
        if (rc != NXPSC_OK) {
            return rc;
        }
    } else {
        memcpy(cmd + 3, data, MFP_BLOCK_SIZE);
    }

    uint8_t mac[8] = {0};
    int rc = plus_mac(card, MAC_WRITE_CMD, block, 1, cmd, 3 + MFP_BLOCK_SIZE, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }
    memcpy(cmd + 3 + MFP_BLOCK_SIZE, mac, sizeof(mac));

    uint8_t resp[32] = {0};
    size_t resp_len = 0;

    rc = plus_transceive(card, cmd, sizeof(cmd), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    card->plus_w_ctr++;
    return NXPSC_OK;
}

int nxpsc_plus_write(nxpsc_card_t *card, uint16_t block, const uint8_t *data, size_t len,
                     bool encrypted) {
    // base opcode 0xA1, bit 1 disables encryption
    uint8_t opcode = encrypted ? MFP_WRITE_ENC : MFP_WRITE_PLAIN;
    return plus_write_block(card, opcode, block, data, len, encrypted);
}

int nxpsc_plus_write_perso(nxpsc_card_t *card, uint16_t block, const uint8_t *data, size_t len) {
    if (card == NULL || data == NULL || len != MFP_BLOCK_SIZE) {
        return NXPSC_E_PARAM;
    }

    // personalisation runs before any session exists, so the frame is plain
    uint8_t cmd[3 + MFP_BLOCK_SIZE] = {MFP_WRITEPERSO,
                                       (uint8_t)(block & 0xFF),
                                       (uint8_t)((block >> 8) & 0xFF)
                                      };
    memcpy(cmd + 3, data, MFP_BLOCK_SIZE);

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return plus_transceive(card, cmd, sizeof(cmd), resp, sizeof(resp), &resp_len);
}

int nxpsc_plus_commit_perso(nxpsc_card_t *card) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t cmd[1] = {MFP_COMMITPERSO};
    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return plus_transceive(card, cmd, sizeof(cmd), resp, sizeof(resp), &resp_len);
}

int nxpsc_plus_value_op(nxpsc_card_t *card, uint16_t block, int32_t delta, bool credit,
                        bool encrypted) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    // the value travels as a full block, the upper 12 bytes stay zero
    uint8_t value[MFP_BLOCK_SIZE] = {0};
    uint32_t raw = (uint32_t)delta;

    value[0] = (uint8_t)(raw & 0xFF);
    value[1] = (uint8_t)((raw >> 8) & 0xFF);
    value[2] = (uint8_t)((raw >> 16) & 0xFF);
    value[3] = (uint8_t)((raw >> 24) & 0xFF);

    uint8_t opcode = credit ? MFP_INCREMENT_ENC : MFP_DECREMENT_ENC;
    if (encrypted == false) {
        opcode ^= 0x02;
    }
    return plus_write_block(card, opcode, block, value, sizeof(value), encrypted);
}

int nxpsc_plus_transfer(nxpsc_card_t *card, uint16_t block) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    uint8_t cmd[3 + 8] = {MFP_TRANSFER, (uint8_t)(block & 0xFF), (uint8_t)((block >> 8) & 0xFF)};
    uint8_t mac[8] = {0};

    int rc = plus_mac(card, MAC_WRITE_CMD, block, 1, cmd, 3, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }
    memcpy(cmd + 3, mac, sizeof(mac));

    uint8_t resp[32] = {0};
    size_t resp_len = 0;

    rc = plus_transceive(card, cmd, sizeof(cmd), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    card->plus_w_ctr++;
    return NXPSC_OK;
}

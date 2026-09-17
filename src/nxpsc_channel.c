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
// libnxpsc - secure channels, D40 / EV1 / EV2 / LRP
//-----------------------------------------------------------------------------

#include "nxpsc_internal.h"

#include <stdlib.h>
#include <string.h>

//-----------------------------------------------------------------------------
// command metadata
//-----------------------------------------------------------------------------
#define HDR_LEN_ALL             0xFFFF
#define HDR_LEN_ALL_EXCEPT_MAC  0xFFFE

typedef struct {
    uint8_t cmd;
    uint16_t len;
} cmd_header_t;

// number of leading bytes that stay in the clear, the rest of the payload is
// what gets enciphered
static const cmd_header_t cmd_headers[] = {
    {DF_CREATE_APPLICATION,    HDR_LEN_ALL},
    {DF_DELETE_APPLICATION,    HDR_LEN_ALL},
    {DF_CHANGE_KEY,            1},
    {DF_CHANGE_KEY_EV2,        2},
    {DF_SET_CONFIGURATION,     1},
    {DF_GET_FILE_SETTINGS,     1},
    {DF_CHANGE_FILE_SETTINGS,  1},
    {DF_CREATE_TRANS_MAC_FILE, 5},
    {DF_READ_DATA,             7},
    {DF_WRITE_DATA,            7},
    {DF_READ_RECORDS,          7},
    {DF_WRITE_RECORD,          7},
    {DF_UPDATE_RECORD,        10},
    {DF_GET_VALUE,             1},
    {DF_CREDIT,                1},
    {DF_DEBIT,                 1},
    {DF_LIMITED_CREDIT,        1},
};

static size_t cmd_header_len(uint8_t cmd, size_t data_len) {
    for (size_t i = 0; i < sizeof(cmd_headers) / sizeof(cmd_headers[0]); i++) {
        if (cmd_headers[i].cmd != cmd) {
            continue;
        }
        if (cmd_headers[i].len == HDR_LEN_ALL) {
            return data_len;
        }
        if (cmd_headers[i].len == HDR_LEN_ALL_EXCEPT_MAC) {
            return (data_len >= 8) ? data_len - 8 : data_len;
        }
        return cmd_headers[i].len;
    }
    return 0;
}

// commands whose request carries a MAC on the D40 and EV1 channels
static const uint8_t tx_mac_cmds[] = {
    DF_WRITE_DATA, DF_CREDIT, DF_DEBIT, DF_LIMITED_CREDIT, DF_WRITE_RECORD,
    DF_UPDATE_RECORD, DF_COMMIT_READER_ID, DF_INIT_KEY_SETTINGS,
    DF_ROLL_KEY_SETTINGS, DF_FINALIZE_KEY_SETTINGS,
};

static bool transmits_mac(const nxpsc_card_t *card, uint8_t cmd) {
    if (card->channel != NXPSC_CHAN_D40 && card->channel != NXPSC_CHAN_EV1) {
        return true;
    }
    for (size_t i = 0; i < sizeof(tx_mac_cmds); i++) {
        if (tx_mac_cmds[i] == cmd) {
            return true;
        }
    }
    return false;
}

// commands whose D40 response carries a MAC
static const uint8_t rx_mac_cmds[] = {
    DF_READ_DATA, DF_READ_RECORDS, DF_GET_VALUE,
};

static bool receives_mac(const nxpsc_card_t *card, uint8_t cmd) {
    if (card->channel != NXPSC_CHAN_D40) {
        return true;
    }
    for (size_t i = 0; i < sizeof(rx_mac_cmds); i++) {
        if (rx_mac_cmds[i] == cmd) {
            return true;
        }
    }
    return false;
}

//-----------------------------------------------------------------------------
// helpers
//-----------------------------------------------------------------------------
static size_t block_len(const nxpsc_card_t *card) {
    return nxpsc_block_size(card->key_type);
}

// walks back over the trailing zeros and checks the CRC of every plausible
// position, the payload may legitimately end in 0x00 or the 0x80 pad byte
size_t nxpsc_search_crc_pos(const uint8_t *data, size_t len, uint8_t status, uint8_t crc_len) {
    if (len < crc_len) {
        return 0;
    }

    size_t pos = len - 1;
    while (pos > 0 && data[pos] == 0) {
        pos--;
    }
    pos++;

    if (pos < crc_len) {
        return 0;
    }

    size_t found = 0;
    uint8_t buffer[NXPSC_MAX_RESPONSE + 1];

    for (int i = 0; i < crc_len + 2; i++) {
        if ((size_t)i > pos || pos - i == 0) {
            break;
        }
        size_t candidate = pos - i;
        if (candidate + crc_len > len || candidate + 1 > sizeof(buffer)) {
            continue;
        }

        uint8_t crc[4] = {0};
        if (crc_len == 4) {
            memcpy(buffer, data, candidate);
            buffer[candidate] = status;
            nxpsc_crc32(buffer, candidate + 1, crc);
        } else {
            nxpsc_crc16(data, candidate, crc);
        }

        if (memcmp(crc, data + candidate, crc_len) == 0) {
            found = candidate;
        }
    }
    return found;
}

static size_t iso9797_m2_len(const uint8_t *data, size_t len) {
    for (size_t i = len; i > 0; i--) {
        if (data[i - 1] == 0x80) {
            return i - 1;
        }
        if (data[i - 1] != 0x00) {
            return 0;
        }
    }
    return 0;
}

static int copy_output(uint8_t *dst, size_t cap, const uint8_t *src, size_t len, size_t *dst_len) {
    if (len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (len > 0) {
        memcpy(dst, src, len);
    }
    *dst_len = len;
    return NXPSC_OK;
}

// EV2 IV, AN12343. E(SesAuthENCKey, 0xA55A|0x5AA5 || TI || CmdCtr || zeros)
void nxpsc_ev2_fill_iv(nxpsc_card_t *card, bool for_command, uint8_t *iv) {
    uint8_t buf[NXPSC_AES_BLOCK] = {0};

    if (for_command) {
        buf[0] = 0xA5;
        buf[1] = 0x5A;
    } else {
        buf[0] = 0x5A;
        buf[1] = 0xA5;
    }

    memcpy(buf + 2, card->ti, 4);
    buf[6] = (uint8_t)(card->cmd_ctr & 0xFF);
    buf[7] = (uint8_t)((card->cmd_ctr >> 8) & 0xFF);

    nxpsc_ecb_encrypt_block(NXPSC_KEY_AES128, card->session_enc, buf, buf);
    memcpy(iv, buf, NXPSC_AES_BLOCK);
}

// EV2 MAC input, Cmd || CmdCtr || TI || CmdData
int nxpsc_ev2_cmac(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                    uint8_t *mac8) {
    size_t total = 7 + len;
    uint8_t *buf = calloc(total, 1);
    if (buf == NULL) {
        return NXPSC_E_MEMORY;
    }

    buf[0] = cmd;
    buf[1] = (uint8_t)(card->cmd_ctr & 0xFF);
    buf[2] = (uint8_t)((card->cmd_ctr >> 8) & 0xFF);
    memcpy(buf + 3, card->ti, 4);
    if (len > 0) {
        memcpy(buf + 7, data, len);
    }

    uint8_t full[NXPSC_AES_BLOCK] = {0};
    uint8_t iv[NXPSC_AES_BLOCK] = {0};
    int rc = NXPSC_OK;

    if (card->channel == NXPSC_CHAN_LRP) {
        nxpsc_lrp_ctx_t lrp;
        nxpsc_lrp_init(&lrp, card->session_mac, 0, true);
        nxpsc_lrp_cmac8(&lrp, buf, total, mac8);
    } else {
        rc = nxpsc_cmac(NXPSC_KEY_AES128, card->session_mac, iv, buf, total, 0, full);
        if (rc == NXPSC_OK) {
            nxpsc_truncate_mac(full, mac8);
        }
    }

    free(buf);
    return rc;
}

//-----------------------------------------------------------------------------
// encode
//-----------------------------------------------------------------------------
static int encode_d40(nxpsc_card_t *card, uint8_t cmd, const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t cap, size_t *dst_len) {
    size_t bs = block_len(card);
    size_t hdr = cmd_header_len(cmd, src_len);
    if (hdr > src_len) {
        hdr = src_len;
    }

    if (src_len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (src_len > 0) {
        memcpy(dst, src, src_len);
    }
    *dst_len = src_len;

    if (card->mode == MODE_MAC || (card->mode == MODE_ENC && src_len <= hdr)) {
        if (src_len == 0) {
            return NXPSC_OK;
        }

        size_t mac_len = nxpsc_mac_length(card);
        size_t plen = nxpsc_padded_len(src_len - hdr, bs);
        if (plen == 0) {
            return NXPSC_OK;
        }

        uint8_t *buf = calloc(plen, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }
        memcpy(buf, src + hdr, src_len - hdr);

        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        // verifying a MAC is the same operation on both sides, so the encrypt
        // primitive is correct here even on D40
        int rc = nxpsc_cbc_crypt_ex(card->key_type, card->session_mac, iv, buf, plen, buf, true, true);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (transmits_mac(card, cmd)) {
            if (src_len + mac_len > cap) {
                return NXPSC_E_LENGTH;
            }
            memcpy(dst + src_len, iv, mac_len);
            *dst_len = src_len + mac_len;
        }
        return NXPSC_OK;
    }

    if (card->mode == MODE_ENC || card->mode == MODE_ENC_PADDED) {
        if (src_len <= hdr) {
            return NXPSC_OK;
        }

        size_t pad = (card->mode == MODE_ENC_PADDED) ? 1 : 0;
        size_t plen = nxpsc_padded_len(src_len + 2 + pad - hdr, bs);
        if (hdr + plen > cap) {
            return NXPSC_E_LENGTH;
        }

        uint8_t *buf = calloc(plen, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }

        memcpy(buf, src + hdr, src_len - hdr);
        nxpsc_crc16(buf, src_len - hdr, buf + src_len - hdr);
        if (pad > 0) {
            buf[src_len - hdr + 2] = 0x80;
        }

        memcpy(dst, src, hdr);
        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        // D40 silicon only encrypts, the reader mirrors that with decrypt
        int rc = nxpsc_cbc_crypt_ex(card->key_type, card->session_enc, iv, buf, plen,
                                    dst + hdr, true, false);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        *dst_len = hdr + plen;
        return NXPSC_OK;
    }

    if (card->mode == MODE_ENC_PLAIN) {
        if (src_len <= hdr) {
            return NXPSC_OK;
        }

        size_t plen = nxpsc_padded_len(src_len - hdr, bs);
        if (hdr + plen > cap) {
            return NXPSC_E_LENGTH;
        }

        uint8_t *buf = calloc(plen, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }
        memcpy(buf, src + hdr, src_len - hdr);

        memcpy(dst, src, hdr);
        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        int rc = nxpsc_cbc_crypt_ex(card->key_type, card->session_enc, iv, buf, plen,
                                    dst + hdr, true, false);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        *dst_len = hdr + plen;
        card->mode = MODE_ENC;
        return NXPSC_OK;
    }

    return NXPSC_OK;
}

static int encode_ev1(nxpsc_card_t *card, uint8_t cmd, const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t cap, size_t *dst_len) {
    size_t bs = block_len(card);
    size_t hdr = cmd_header_len(cmd, src_len);
    if (hdr > src_len) {
        hdr = src_len;
    }

    if (src_len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (src_len > 0) {
        memcpy(dst, src, src_len);
    }
    *dst_len = src_len;

    // the MAC is computed for every command, it also advances the IV
    if (card->mode == MODE_PLAIN || card->mode == MODE_MAC ||
            (card->mode == MODE_ENC && src_len <= hdr)) {

        uint8_t *buf = calloc(src_len + 1, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }
        buf[0] = cmd;
        if (src_len > 0) {
            memcpy(buf + 1, src, src_len);
        }

        uint8_t cmac[NXPSC_MAX_BLOCK] = {0};
        int rc = nxpsc_cmac(card->key_type, card->session_mac, card->iv, buf, src_len + 1, 0, cmac);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (card->mode == MODE_MAC && transmits_mac(card, cmd)) {
            size_t mac_len = nxpsc_mac_length(card);
            if (src_len + mac_len > cap) {
                return NXPSC_E_LENGTH;
            }
            memcpy(dst + src_len, cmac, mac_len);
            *dst_len = src_len + mac_len;
        }
        return NXPSC_OK;
    }

    if (card->mode == MODE_ENC || card->mode == MODE_ENC_PADDED) {
        size_t pad = (card->mode == MODE_ENC_PADDED) ? 1 : 0;
        size_t plen = nxpsc_padded_len(src_len + 4 + pad - hdr, bs);
        if (hdr + plen > cap) {
            return NXPSC_E_LENGTH;
        }

        uint8_t *buf = calloc(plen + hdr + 8, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }

        // CRC32 covers the command byte and the whole payload
        buf[0] = cmd;
        memcpy(buf + 1, src, src_len);
        nxpsc_crc32(buf, src_len + 1, buf + src_len + 1);
        if (pad > 0) {
            buf[src_len + 1 + 4] = 0x80;
        }

        memcpy(dst, src, hdr);
        int rc = nxpsc_cbc_crypt(card->key_type, card->session_enc, card->iv,
                                 buf + 1 + hdr, plen, dst + hdr, true);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        *dst_len = hdr + plen;
        card->mode = MODE_ENC;
        return NXPSC_OK;
    }

    if (card->mode == MODE_ENC_PLAIN) {
        if (src_len <= hdr) {
            return NXPSC_OK;
        }

        size_t plen = nxpsc_padded_len(src_len - hdr, bs);
        if (hdr + plen > cap) {
            return NXPSC_E_LENGTH;
        }

        uint8_t *buf = calloc(plen, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }
        memcpy(buf, src + hdr, src_len - hdr);

        memcpy(dst, src, hdr);
        int rc = nxpsc_cbc_crypt(card->key_type, card->session_enc, card->iv, buf, plen,
                                 dst + hdr, true);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        *dst_len = hdr + plen;
        card->mode = MODE_ENC;
        return NXPSC_OK;
    }

    return NXPSC_OK;
}

static int encode_ev2(nxpsc_card_t *card, uint8_t cmd, const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t cap, size_t *dst_len) {
    size_t mac_len = nxpsc_mac_length(card);
    size_t hdr = cmd_header_len(cmd, src_len);
    if (hdr > src_len) {
        hdr = src_len;
    }

    if (src_len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (src_len > 0) {
        memcpy(dst, src, src_len);
    }
    *dst_len = src_len;

    if (card->mode == MODE_MAC) {
        uint8_t mac[8] = {0};
        int rc = nxpsc_ev2_cmac(card, cmd, src, src_len, mac);
        if (rc != NXPSC_OK) {
            return rc;
        }
        if (src_len + mac_len > cap) {
            return NXPSC_E_LENGTH;
        }
        memcpy(dst + src_len, mac, mac_len);
        *dst_len = src_len + mac_len;
        return NXPSC_OK;
    }

    if (card->mode == MODE_ENC || card->mode == MODE_ENC_PADDED || card->mode == MODE_ENC_PLAIN) {
        memcpy(dst, src, hdr);
        size_t plen = 0;

        if (src_len > hdr) {
            plen = nxpsc_padded_len(src_len + 1 - hdr, NXPSC_AES_BLOCK);
            if (hdr + plen + mac_len > cap) {
                return NXPSC_E_LENGTH;
            }

            uint8_t *buf = calloc(plen, 1);
            if (buf == NULL) {
                return NXPSC_E_MEMORY;
            }
            memcpy(buf, src + hdr, src_len - hdr);
            buf[src_len - hdr] = 0x80;

            int rc;
            if (card->channel == NXPSC_CHAN_LRP) {
                size_t out_len = 0;
                nxpsc_lrp_ctx_t lrp;
                nxpsc_lrp_init(&lrp, card->session_enc, 1, false);
                nxpsc_lrp_set_counter(&lrp, card->iv, 4 * 2);
                rc = nxpsc_lrp_encode(&lrp, buf, plen, dst + hdr, cap - hdr, &out_len);
                memcpy(card->iv, lrp.counter, 4);
            } else {
                uint8_t iv[NXPSC_AES_BLOCK] = {0};
                nxpsc_ev2_fill_iv(card, true, iv);
                rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, card->session_enc, iv, buf, plen,
                                     dst + hdr, true);
            }
            free(buf);
            if (rc != NXPSC_OK) {
                return rc;
            }
        }

        uint8_t mac[8] = {0};
        int rc = nxpsc_ev2_cmac(card, cmd, dst, hdr + plen, mac);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (hdr + plen + mac_len > cap) {
            return NXPSC_E_LENGTH;
        }
        memcpy(dst + hdr + plen, mac, mac_len);
        *dst_len = hdr + plen + mac_len;
        card->mode = MODE_ENC;
        return NXPSC_OK;
    }

    return NXPSC_OK;
}

int nxpsc_channel_encode(nxpsc_card_t *card, uint8_t cmd, const uint8_t *src, size_t src_len,
                         uint8_t *dst, size_t cap, size_t *dst_len) {
    if (card == NULL || dst == NULL || dst_len == NULL || (src_len > 0 && src == NULL)) {
        return NXPSC_E_PARAM;
    }

    card->last_cmd = cmd;
    card->last_request_zero_len = (src_len <= cmd_header_len(cmd, src_len));

    switch (card->channel) {
        case NXPSC_CHAN_D40:
            return encode_d40(card, cmd, src, src_len, dst, cap, dst_len);
        case NXPSC_CHAN_EV1:
            return encode_ev1(card, cmd, src, src_len, dst, cap, dst_len);
        case NXPSC_CHAN_EV2:
        case NXPSC_CHAN_LRP:
            return encode_ev2(card, cmd, src, src_len, dst, cap, dst_len);
        default:
            break;
    }

    if (src_len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (src_len > 0) {
        memcpy(dst, src, src_len);
    }
    *dst_len = src_len;
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// decode
//-----------------------------------------------------------------------------
static int decode_d40(nxpsc_card_t *card, const uint8_t *src, size_t src_len, uint8_t status,
                      uint8_t *dst, size_t cap, size_t *dst_len) {
    size_t bs = block_len(card);

    if (card->mode == MODE_MAC) {
        size_t mac_len = nxpsc_mac_length(card);
        if (receives_mac(card, card->last_cmd) == false) {
            return copy_output(dst, cap, src, src_len, dst_len);
        }
        if (src_len <= mac_len) {
            return NXPSC_E_LENGTH;
        }

        size_t plen = nxpsc_padded_len(src_len - mac_len, bs);
        uint8_t *buf = calloc(plen, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }
        memcpy(buf, src, src_len - mac_len);

        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        int rc = nxpsc_cbc_crypt_ex(card->key_type, card->session_mac, iv, buf, plen, buf, true, true);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (nxpsc_memeq(iv, src + src_len - mac_len, mac_len) == false) {
            card->mac_mismatch = true;
            return NXPSC_E_CRYPTO;
        }
        return copy_output(dst, cap, src, src_len - mac_len, dst_len);
    }

    if (card->mode == MODE_ENC || card->mode == MODE_ENC_PADDED) {
        uint8_t plain[NXPSC_MAX_RESPONSE] = {0};

        if (src_len < bs) {
            return copy_output(dst, cap, src, src_len, dst_len);
        }

        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        int rc = nxpsc_cbc_crypt_ex(card->key_type, card->session_enc, iv, src, src_len, plain,
                                    false, false);
        if (rc != NXPSC_OK) {
            return rc;
        }

        size_t pure = nxpsc_search_crc_pos(plain, src_len, status, 2);
        if (pure == 0 && card->type != DESFIRE_MF3ICD40) {
            memcpy(iv, card->iv, sizeof(iv));
            rc = nxpsc_cbc_crypt(card->key_type, card->session_enc, iv, src, src_len, plain, false);
            if (rc != NXPSC_OK) {
                return rc;
            }
            pure = nxpsc_search_crc_pos(plain, src_len, status, 4);
        }
        if (pure == 0) {
            return NXPSC_E_CRYPTO;
        }
        return copy_output(dst, cap, plain, pure, dst_len);
    }

    return copy_output(dst, cap, src, src_len, dst_len);
}

static int decode_ev1(nxpsc_card_t *card, const uint8_t *src, size_t src_len, uint8_t status,
                      uint8_t *dst, size_t cap, size_t *dst_len) {
    size_t bs = block_len(card);
    size_t mac_len = nxpsc_mac_length(card);

    if (card->mode == MODE_PLAIN || card->mode == MODE_MAC ||
            (card->mode == MODE_ENC && card->last_request_zero_len == false)) {

        if (src_len < mac_len) {
            return NXPSC_E_LENGTH;
        }

        size_t data_len = src_len - mac_len;

        uint8_t *buf = calloc(data_len + 1, 1);
        if (buf == NULL) {
            return NXPSC_E_MEMORY;
        }
        memcpy(buf, src, data_len);
        buf[data_len] = status;

        uint8_t cmac[NXPSC_MAX_BLOCK] = {0};
        int rc = nxpsc_cmac(card->key_type, card->session_mac, card->iv, buf, data_len + 1, 0, cmac);
        free(buf);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (nxpsc_memeq(src + data_len, cmac, mac_len) == false) {
            card->mac_mismatch = true;
            return NXPSC_E_CRYPTO;
        }
        return copy_output(dst, cap, src, data_len, dst_len);
    }

    if (card->mode == MODE_ENC || card->mode == MODE_ENC_PADDED) {
        uint8_t plain[NXPSC_MAX_RESPONSE] = {0};

        if (src_len < bs) {
            return copy_output(dst, cap, src, src_len, dst_len);
        }

        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        memcpy(iv, card->iv, sizeof(iv));
        int rc = nxpsc_cbc_crypt(card->key_type, card->session_enc, iv, src, src_len, plain, false);
        if (rc != NXPSC_OK) {
            return rc;
        }

        size_t pure = nxpsc_search_crc_pos(plain, src_len, status, 4);
        if (pure == 0) {
            return NXPSC_E_CRYPTO;
        }
        return copy_output(dst, cap, plain, pure, dst_len);
    }

    return copy_output(dst, cap, src, src_len, dst_len);
}

static int decode_ev2(nxpsc_card_t *card, const uint8_t *src, size_t src_len, uint8_t status,
                      uint8_t *dst, size_t cap, size_t *dst_len) {
    (void)status;

    size_t mac_len = nxpsc_mac_length(card);

    if (card->mode != MODE_MAC && card->mode != MODE_ENC && card->mode != MODE_ENC_PADDED) {
        return copy_output(dst, cap, src, src_len, dst_len);
    }

    if (src_len < mac_len) {
        return NXPSC_E_LENGTH;
    }

    size_t data_len = src_len - mac_len;
    uint8_t mac[8] = {0};
    int rc = nxpsc_ev2_cmac(card, 0x00, src, data_len, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (nxpsc_memeq(src + data_len, mac, mac_len) == false) {
        card->mac_mismatch = true;
        return NXPSC_E_CRYPTO;
    }

    if (card->mode == MODE_MAC || data_len < NXPSC_AES_BLOCK) {
        return copy_output(dst, cap, src, data_len, dst_len);
    }

    uint8_t plain[NXPSC_MAX_RESPONSE] = {0};
    if (card->channel == NXPSC_CHAN_LRP) {
        size_t out_len = 0;
        nxpsc_lrp_ctx_t lrp;
        nxpsc_lrp_init(&lrp, card->session_enc, 1, false);
        nxpsc_lrp_set_counter(&lrp, card->iv, 4 * 2);
        rc = nxpsc_lrp_decode(&lrp, src, data_len, plain, sizeof(plain), &out_len);
        memcpy(card->iv, lrp.counter, 4);
    } else {
        uint8_t iv[NXPSC_AES_BLOCK] = {0};
        nxpsc_ev2_fill_iv(card, false, iv);
        rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, card->session_enc, iv, src, data_len, plain, false);
    }

    if (rc != NXPSC_OK) {
        return rc;
    }

    size_t pure = iso9797_m2_len(plain, data_len);
    if (pure == 0) {
        return NXPSC_E_CRYPTO;
    }
    return copy_output(dst, cap, plain, pure, dst_len);
}

int nxpsc_channel_decode(nxpsc_card_t *card, const uint8_t *src, size_t src_len, uint8_t status,
                         uint8_t *dst, size_t cap, size_t *dst_len) {
    if (card == NULL || dst == NULL || dst_len == NULL) {
        return NXPSC_E_PARAM;
    }

    switch (card->channel) {
        case NXPSC_CHAN_D40:
            return decode_d40(card, src, src_len, status, dst, cap, dst_len);
        case NXPSC_CHAN_EV1:
            return decode_ev1(card, src, src_len, status, dst, cap, dst_len);
        case NXPSC_CHAN_EV2:
        case NXPSC_CHAN_LRP:
            return decode_ev2(card, src, src_len, status, dst, cap, dst_len);
        default:
            break;
    }

    if (src_len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (src_len > 0) {
        memcpy(dst, src, src_len);
    }
    *dst_len = src_len;
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// authentication
//-----------------------------------------------------------------------------
static void rol(uint8_t *data, size_t len) {
    uint8_t first = data[0];
    memmove(data, data + 1, len - 1);
    data[len - 1] = first;
}

static nxpsc_channel_t pick_channel(const nxpsc_card_t *card, const nxpsc_key_t *key) {
    switch (card->type) {
        case DESFIRE_MF3ICD40:
            return NXPSC_CHAN_D40;
        case DESFIRE_EV2:
        case DESFIRE_EV2_XL:
        case DESFIRE_EV3:
            // these still hold (2K3)DES keys, e.g. the factory PICC master key
            if (key->type == NXPSC_KEY_DES || key->type == NXPSC_KEY_2K3DES) {
                return NXPSC_CHAN_D40;
            }
            if (key->type == NXPSC_KEY_3K3DES) {
                return NXPSC_CHAN_EV1;
            }
            return NXPSC_CHAN_EV2;
        case DESFIRE_LIGHT:
        case NTAG424:
        case DUOX:
            return NXPSC_CHAN_EV2;
        case DESFIRE_EV1:
        case NTAG413DNA:
            if (key->type == NXPSC_KEY_DES || key->type == NXPSC_KEY_2K3DES) {
                return NXPSC_CHAN_D40;
            }
            return NXPSC_CHAN_EV1;
        default:
            break;
    }
    // unknown card, AES keys never work on the legacy channel
    return (key->type == NXPSC_KEY_DES) ? NXPSC_CHAN_D40 : NXPSC_CHAN_EV1;
}

// legacy 0x0A and EV1 0x1A / 0xAA three pass authentication
static int auth_legacy(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key,
                       nxpsc_channel_t channel) {
    size_t rnd_len = (key->type == NXPSC_KEY_AES128 || key->type == NXPSC_KEY_AES256 ||
                      key->type == NXPSC_KEY_3K3DES) ? 16 : 8;

    uint8_t cmd = DF_AUTHENTICATE;
    if (channel == NXPSC_CHAN_EV1) {
        cmd = (key->type == NXPSC_KEY_AES128 || key->type == NXPSC_KEY_AES256)
              ? DF_AUTHENTICATE_AES : DF_AUTHENTICATE_ISO;
    }

    uint8_t status = 0;
    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_raw_exchange_ex(card, cmd, &key_no, 1, &status, resp, sizeof(resp), &resp_len,
                                   false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (status != DF_S_ADDITIONAL_FRAME || resp_len != rnd_len) {
        return NXPSC_E_AUTH;
    }

    uint8_t rnd_a[16] = {0};
    uint8_t rnd_b[16] = {0};
    uint8_t rot_b[16] = {0};
    uint8_t iv[NXPSC_MAX_BLOCK] = {0};

    rc = nxpsc_random_bytes(rnd_a, rnd_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    rc = nxpsc_cbc_crypt_ex(key->type, key->data, iv, resp, rnd_len, rnd_b, false, false);
    if (rc != NXPSC_OK) {
        return rc;
    }

    memcpy(rot_b, rnd_b, rnd_len);
    rol(rot_b, rnd_len);

    uint8_t both[32] = {0};

    if (channel == NXPSC_CHAN_D40) {
        // MF3ICD40 can only encrypt, the reader side runs the decrypt primitive
        uint8_t enc_a[16] = {0};
        memset(iv, 0, sizeof(iv));
        rc = nxpsc_cbc_crypt_ex(key->type, key->data, iv, rnd_a, rnd_len, enc_a, true, false);
        if (rc != NXPSC_OK) {
            return rc;
        }
        memcpy(both, enc_a, rnd_len);

        nxpsc_xor(rot_b, enc_a, rnd_len);
        memset(iv, 0, sizeof(iv));
        rc = nxpsc_cbc_crypt_ex(key->type, key->data, iv, rot_b, rnd_len, both + rnd_len, true, false);
        if (rc != NXPSC_OK) {
            return rc;
        }
    } else {
        uint8_t tmp[32] = {0};
        memcpy(tmp, rnd_a, rnd_len);
        memcpy(tmp + rnd_len, rot_b, rnd_len);
        memset(iv, 0, sizeof(iv));
        rc = nxpsc_cbc_crypt_ex(key->type, key->data, iv, tmp, rnd_len * 2, both, true, true);
        if (rc != NXPSC_OK) {
            return rc;
        }
    }

    rc = nxpsc_raw_exchange_ex(card, DF_ADDITIONAL_FRAME, both, rnd_len * 2, &status,
                               resp, sizeof(resp), &resp_len, false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (status != DF_S_OK || resp_len != rnd_len) {
        return NXPSC_E_AUTH;
    }

    uint8_t enc_rnd_a[16] = {0};
    if (channel == NXPSC_CHAN_D40) {
        memset(iv, 0, sizeof(iv));
    }
    rc = nxpsc_cbc_crypt_ex(key->type, key->data, iv, resp, rnd_len, enc_rnd_a, false, false);
    if (rc != NXPSC_OK) {
        return rc;
    }

    uint8_t session[NXPSC_MAX_KEY_SIZE] = {0};
    nxpsc_session_key_d40(rnd_a, rnd_b, key->type, session);

    rol(rnd_a, rnd_len);
    if (nxpsc_memeq(rnd_a, enc_rnd_a, rnd_len) == false) {
        nxpsc_secure_zero(rnd_a, sizeof(rnd_a));
        nxpsc_secure_zero(rnd_b, sizeof(rnd_b));
        nxpsc_secure_zero(rot_b, sizeof(rot_b));
        nxpsc_secure_zero(enc_rnd_a, sizeof(enc_rnd_a));
        nxpsc_secure_zero(session, sizeof(session));
        return NXPSC_E_AUTH;
    }

    card->channel = channel;
    card->key_type = key->type;
    card->key_no = key_no;
    memcpy(card->key, key->data, nxpsc_key_size(key->type));
    memcpy(card->session_enc, session, nxpsc_key_size(key->type));
    memcpy(card->session_mac, session, nxpsc_key_size(key->type));
    memset(card->iv, 0, sizeof(card->iv));
    card->authenticated = true;
    nxpsc_secure_zero(rnd_a, sizeof(rnd_a));
    nxpsc_secure_zero(rnd_b, sizeof(rnd_b));
    nxpsc_secure_zero(rot_b, sizeof(rot_b));
    nxpsc_secure_zero(enc_rnd_a, sizeof(enc_rnd_a));
    nxpsc_secure_zero(session, sizeof(session));
    return NXPSC_OK;
}

// AuthenticateEV2First / NonFirst, AN12343
static int auth_ev2(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key, bool first) {
    uint8_t cmd = first ? DF_AUTHENTICATE_EV2F : DF_AUTHENTICATE_EV2NF;
    uint8_t cdata[2] = {key_no, 0x00};
    uint8_t status = 0;
    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_raw_exchange_ex(card, cmd, cdata, first ? 2 : 1, &status,
                                   resp, sizeof(resp), &resp_len, false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (status != DF_S_ADDITIONAL_FRAME) {
        return NXPSC_E_AUTH;
    }

    size_t offset = 0;
    if (resp_len == NXPSC_AES_BLOCK + 1) {
        if (resp[0] != 0x00) {
            return NXPSC_E_AUTH;
        }
        offset = 1;
    } else if (resp_len != NXPSC_AES_BLOCK) {
        return NXPSC_E_LENGTH;
    }

    uint8_t rnd_a[NXPSC_AES_BLOCK] = {0};
    uint8_t rnd_b[NXPSC_AES_BLOCK] = {0};
    uint8_t iv[NXPSC_AES_BLOCK] = {0};

    rc = nxpsc_random_bytes(rnd_a, sizeof(rnd_a));
    if (rc != NXPSC_OK) {
        return rc;
    }

    rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, key->data, iv, resp + offset, NXPSC_AES_BLOCK,
                         rnd_b, false);
    if (rc != NXPSC_OK) {
        return rc;
    }

    uint8_t rot_b[NXPSC_AES_BLOCK] = {0};
    memcpy(rot_b, rnd_b, sizeof(rot_b));
    rol(rot_b, sizeof(rot_b));

    uint8_t tmp[NXPSC_AES_BLOCK * 2] = {0};
    memcpy(tmp, rnd_a, NXPSC_AES_BLOCK);
    memcpy(tmp + NXPSC_AES_BLOCK, rot_b, NXPSC_AES_BLOCK);

    uint8_t both[NXPSC_AES_BLOCK * 2] = {0};
    memset(iv, 0, sizeof(iv));
    rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, key->data, iv, tmp, sizeof(tmp), both, true);
    if (rc != NXPSC_OK) {
        return rc;
    }

    rc = nxpsc_raw_exchange_ex(card, DF_ADDITIONAL_FRAME, both, sizeof(both), &status,
                               resp, sizeof(resp), &resp_len, false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (status != DF_S_OK) {
        return NXPSC_E_AUTH;
    }

    size_t need = first ? (NXPSC_AES_BLOCK * 2) : NXPSC_AES_BLOCK;
    if (resp_len != need) {
        return NXPSC_E_LENGTH;
    }

    uint8_t data[64] = {0};
    memset(iv, 0, sizeof(iv));
    rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, key->data, iv, resp, resp_len, data, false);
    if (rc != NXPSC_OK) {
        return rc;
    }

    uint8_t ret_rnd_a[NXPSC_AES_BLOCK] = {0};
    if (first) {
        ret_rnd_a[0] = data[19];
        memcpy(ret_rnd_a + 1, data + 4, NXPSC_AES_BLOCK - 1);
    } else {
        ret_rnd_a[0] = data[15];
        memcpy(ret_rnd_a + 1, data, NXPSC_AES_BLOCK - 1);
    }

    if (nxpsc_memeq(rnd_a, ret_rnd_a, NXPSC_AES_BLOCK) == false) {
        nxpsc_secure_zero(rnd_a, sizeof(rnd_a));
        nxpsc_secure_zero(rnd_b, sizeof(rnd_b));
        nxpsc_secure_zero(rot_b, sizeof(rot_b));
        nxpsc_secure_zero(data, sizeof(data));
        nxpsc_secure_zero(ret_rnd_a, sizeof(ret_rnd_a));
        return NXPSC_E_AUTH;
    }

    if (first) {
        card->cmd_ctr = 0;
        memcpy(card->ti, data, 4);
    }

    memset(card->iv, 0, sizeof(card->iv));
    nxpsc_session_key_ev2(key->data, rnd_a, rnd_b, true, card->session_enc);
    nxpsc_session_key_ev2(key->data, rnd_a, rnd_b, false, card->session_mac);

    card->channel = NXPSC_CHAN_EV2;
    card->key_type = key->type;
    card->key_no = key_no;
    memcpy(card->key, key->data, nxpsc_key_size(key->type));
    card->authenticated = true;
    nxpsc_secure_zero(rnd_a, sizeof(rnd_a));
    nxpsc_secure_zero(rnd_b, sizeof(rnd_b));
    nxpsc_secure_zero(rot_b, sizeof(rot_b));
    nxpsc_secure_zero(data, sizeof(data));
    nxpsc_secure_zero(ret_rnd_a, sizeof(ret_rnd_a));
    return NXPSC_OK;
}

// AuthenticateLRPFirst / NonFirst, MF2DLHX0
static int auth_lrp(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key, bool first) {
    uint8_t cmd = first ? DF_AUTHENTICATE_EV2F : DF_AUTHENTICATE_EV2NF;
    uint8_t cdata[3] = {key_no, 0x01, 0x02};
    uint8_t status = 0;
    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_raw_exchange_ex(card, cmd, cdata, first ? 3 : 1, &status,
                                   resp, sizeof(resp), &resp_len, false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (status != DF_S_ADDITIONAL_FRAME || resp_len != NXPSC_AES_BLOCK + 1 || resp[0] != 0x01) {
        return NXPSC_E_AUTH;
    }

    uint8_t rnd_a[NXPSC_AES_BLOCK] = {0};
    uint8_t rnd_b[NXPSC_AES_BLOCK] = {0};

    rc = nxpsc_random_bytes(rnd_a, sizeof(rnd_a));
    if (rc != NXPSC_OK) {
        return rc;
    }
    // the PICC returns RndB in the clear on the LRP channel
    memcpy(rnd_b, resp + 1, NXPSC_AES_BLOCK);

    uint8_t session[NXPSC_AES_BLOCK] = {0};
    nxpsc_session_key_lrp(key->data, rnd_a, rnd_b, false, session);

    uint8_t tmp[NXPSC_AES_BLOCK * 3] = {0};
    memcpy(tmp, rnd_a, NXPSC_AES_BLOCK);
    memcpy(tmp + NXPSC_AES_BLOCK, rnd_b, NXPSC_AES_BLOCK);

    uint8_t cmac[NXPSC_AES_BLOCK] = {0};
    nxpsc_lrp_ctx_t lrp;
    nxpsc_lrp_init(&lrp, session, 0, true);
    nxpsc_lrp_cmac(&lrp, tmp, NXPSC_AES_BLOCK * 2, cmac);

    uint8_t both[NXPSC_AES_BLOCK * 2] = {0};
    memcpy(both, rnd_a, NXPSC_AES_BLOCK);
    memcpy(both + NXPSC_AES_BLOCK, cmac, NXPSC_AES_BLOCK);

    rc = nxpsc_raw_exchange_ex(card, DF_ADDITIONAL_FRAME, both, sizeof(both), &status,
                               resp, sizeof(resp), &resp_len, false);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (status != DF_S_OK || resp_len < NXPSC_AES_BLOCK) {
        return NXPSC_E_AUTH;
    }

    memset(card->iv, 0, sizeof(card->iv));

    memcpy(tmp, rnd_b, NXPSC_AES_BLOCK);
    memcpy(tmp + NXPSC_AES_BLOCK, rnd_a, NXPSC_AES_BLOCK);
    if (first) {
        memcpy(tmp + NXPSC_AES_BLOCK * 2, resp, NXPSC_AES_BLOCK);
    }

    nxpsc_lrp_init(&lrp, session, 0, true);
    nxpsc_lrp_cmac(&lrp, tmp, first ? NXPSC_AES_BLOCK * 3 : NXPSC_AES_BLOCK * 2, cmac);

    const uint8_t *received = resp + (first ? NXPSC_AES_BLOCK : 0);
    if (resp_len < (size_t)(first ? NXPSC_AES_BLOCK * 2 : NXPSC_AES_BLOCK)) {
        return NXPSC_E_LENGTH;
    }
    if (nxpsc_memeq(received, cmac, NXPSC_AES_BLOCK) == false) {
        nxpsc_secure_zero(rnd_a, sizeof(rnd_a));
        nxpsc_secure_zero(rnd_b, sizeof(rnd_b));
        nxpsc_secure_zero(session, sizeof(session));
        nxpsc_secure_zero(tmp, sizeof(tmp));
        nxpsc_secure_zero(cmac, sizeof(cmac));
        nxpsc_secure_zero(&lrp, sizeof(lrp));
        return NXPSC_E_AUTH;
    }

    if (first) {
        uint8_t data[NXPSC_AES_BLOCK] = {0};
        size_t out_len = 0;
        nxpsc_lrp_init(&lrp, session, 1, false);
        nxpsc_lrp_set_counter(&lrp, card->iv, 4 * 2);
        nxpsc_lrp_decode(&lrp, resp, NXPSC_AES_BLOCK, data, sizeof(data), &out_len);
        memcpy(card->iv, lrp.counter, 4);

        card->cmd_ctr = 0;
        memcpy(card->ti, data, 4);
    }

    memcpy(card->session_enc, session, NXPSC_AES_BLOCK);
    memcpy(card->session_mac, session, NXPSC_AES_BLOCK);

    card->channel = NXPSC_CHAN_LRP;
    card->key_type = key->type;
    card->key_no = key_no;
    memcpy(card->key, key->data, nxpsc_key_size(key->type));
    card->authenticated = true;
    nxpsc_secure_zero(rnd_a, sizeof(rnd_a));
    nxpsc_secure_zero(rnd_b, sizeof(rnd_b));
    nxpsc_secure_zero(session, sizeof(session));
    nxpsc_secure_zero(tmp, sizeof(tmp));
    nxpsc_secure_zero(cmac, sizeof(cmac));
    nxpsc_secure_zero(&lrp, sizeof(lrp));
    return NXPSC_OK;
}

int nxpsc_authenticate(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key,
                       nxpsc_channel_t channel) {
    if (card == NULL || nxpsc_key_is_valid(key) == false) {
        return NXPSC_E_PARAM;
    }

    nxpsc_reset_channel(card);

    nxpsc_channel_t chan = (channel == NXPSC_CHAN_AUTO) ? pick_channel(card, key) : channel;

    if ((chan == NXPSC_CHAN_EV2 || chan == NXPSC_CHAN_LRP) && key->type != NXPSC_KEY_AES128) {
        return NXPSC_E_UNSUPPORTED;
    }

    switch (chan) {
        case NXPSC_CHAN_D40:
        case NXPSC_CHAN_EV1:
            return auth_legacy(card, key_no, key, chan);
        case NXPSC_CHAN_EV2:
            return auth_ev2(card, key_no, key, true);
        case NXPSC_CHAN_LRP:
            return auth_lrp(card, key_no, key, true);
        default:
            break;
    }
    return NXPSC_E_PARAM;
}

int nxpsc_authenticate_nonfirst(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key) {
    if (card == NULL || nxpsc_key_is_valid(key) == false) {
        return NXPSC_E_PARAM;
    }

    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    if (card->channel == NXPSC_CHAN_LRP) {
        return auth_lrp(card, key_no, key, false);
    }
    if (card->channel == NXPSC_CHAN_EV2) {
        return auth_ev2(card, key_no, key, false);
    }
    return NXPSC_E_UNSUPPORTED;
}

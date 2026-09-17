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
// libnxpsc - internal definitions, not part of the installed API
//-----------------------------------------------------------------------------

#ifndef NXPSC_INTERNAL_H__
#define NXPSC_INTERNAL_H__

#include "nxpsc/nxpsc.h"
#include "nxpsc_crypto.h"

//-----------------------------------------------------------------------------
// native DESFire command set. cross checked against libfreefare
// mifare_desfire.c, python-desfire enums/desfire_command.py, RevK DESFireAES
// desfireaes.c and proxmark3 include/protocols.h. where the four disagree the
// NXP data sheet value wins, see README.md
//-----------------------------------------------------------------------------
#define DF_AUTHENTICATE             0x0A
#define DF_AUTHENTICATE_ISO         0x1A
#define DF_AUTHENTICATE_AES         0xAA
// 0x77, not 0x72. python-desfire has 0x72 in its enum, which is a typo
#define DF_AUTHENTICATE_EV2F        0x71
#define DF_AUTHENTICATE_EV2NF       0x77
#define DF_ADDITIONAL_FRAME         0xAF

#define DF_CHANGE_KEY               0xC4
#define DF_CHANGE_KEY_EV2           0xC6
#define DF_GET_KEY_VERSION          0x64
#define DF_GET_KEY_SETTINGS         0x45
#define DF_CHANGE_KEY_SETTINGS      0x54
#define DF_INIT_KEY_SETTINGS        0x56
#define DF_FINALIZE_KEY_SETTINGS    0x57
#define DF_ROLL_KEY_SETTINGS        0x55

#define DF_CREATE_APPLICATION       0xCA
#define DF_DELETE_APPLICATION       0xDA
#define DF_GET_APPLICATION_IDS      0x6A
#define DF_GET_DF_NAMES             0x6D
#define DF_SELECT_APPLICATION       0x5A
#define DF_FORMAT_PICC              0xFC
#define DF_GET_VERSION              0x60
#define DF_GET_CARD_UID             0x51
#define DF_GET_FREE_MEMORY          0x6E
#define DF_SET_CONFIGURATION        0x5C
#define DF_READ_SIG                 0x3C

#define DF_GET_FILE_IDS             0x6F
#define DF_GET_ISO_FILE_IDS         0x61
#define DF_GET_FILE_SETTINGS        0xF5
#define DF_CHANGE_FILE_SETTINGS     0x5F
#define DF_CREATE_STD_DATA_FILE     0xCD
#define DF_CREATE_BACKUP_DATA_FILE  0xCB
#define DF_CREATE_VALUE_FILE        0xCC
#define DF_CREATE_LINEAR_RECORD     0xC1
#define DF_CREATE_CYCLIC_RECORD     0xC0
#define DF_CREATE_TRANS_MAC_FILE    0xCE
#define DF_DELETE_FILE              0xDF

#define DF_READ_DATA                0xBD
#define DF_WRITE_DATA               0x3D
#define DF_GET_VALUE                0x6C
#define DF_CREDIT                   0x0C
#define DF_DEBIT                    0xDC
#define DF_LIMITED_CREDIT           0x1C
#define DF_WRITE_RECORD             0x3B
#define DF_READ_RECORDS             0xBB
#define DF_UPDATE_RECORD            0xDB
#define DF_CLEAR_RECORD_FILE        0xEB
#define DF_COMMIT_TRANSACTION       0xC7
#define DF_ABORT_TRANSACTION        0xA7
#define DF_COMMIT_READER_ID         0xC8
#define DF_NOTIFY_TX_SUCCESS        0xEE

// ISO chaining variants of the file access commands, EV2 and later
#define DF_READ_DATA2               0xAD
#define DF_WRITE_DATA2              0x8D
#define DF_READ_RECORDS2            0xAB
#define DF_WRITE_RECORD2            0x8B
#define DF_UPDATE_RECORD2           0xBA

// delegated application management, EV2 and later
#define DF_CREATE_DELEGATED_APP     0xC9
#define DF_GET_DELEGATE_INFO        0x69

// MIFARE Classic mapping, EV2 XL / EV3
#define DF_CREATE_MFC_MAPPING       0xCF
#define DF_RESTRICT_MFC_UPDATE      0xBF

// proximity check
#define DF_PREPARE_PC               0xF0
#define DF_PROXIMITY_CHECK          0xF2
#define DF_VERIFY_PC                0xFD

// ISO 7816-4
#define ISO_CLA_WRAP                0x90
#define ISO_INS_SELECT              0xA4
#define ISO_INS_READ_BINARY         0xB0
#define ISO_INS_UPDATE_BINARY       0xD6
#define ISO_INS_READ_RECORD         0xB2
#define ISO_INS_APPEND_RECORD       0xE2
#define ISO_INS_GET_CHALLENGE       0x84
#define ISO_INS_EXTERNAL_AUTH       0x82
#define ISO_INS_INTERNAL_AUTH       0x88

// MIFARE Plus, security level 3
#define MFP_WRITEPERSO              0xA8
#define MFP_COMMITPERSO             0xAA
#define MFP_AUTH_FIRST              0x70
#define MFP_AUTH_FIRST_VARIANT      0x73
#define MFP_AUTH_NONFIRST           0x76
#define MFP_READ_PLAIN_MACED        0x36
#define MFP_READ_ENC_MACED          0x30
#define MFP_WRITE_PLAIN             0xA1
#define MFP_WRITE_ENC               0xA0
#define MFP_INCREMENT_ENC           0xB1
#define MFP_DECREMENT_ENC           0xB3
#define MFP_TRANSFER                0xB5
#define MFP_INCREMENT_TRANSFER_ENC  0xB7
#define MFP_DECREMENT_TRANSFER_ENC  0xB9
#define MFP_RESTORE                 0xC3
#define MFP_RESET_AUTH              0x78
#define MFP_SET_CONFIG_SL1          0x44
#define MFP_PERSONALIZE_UID_USAGE   0x40
#define MFP_VC_SUPPORT_LAST_ISO_L3  0x4B

// status bytes
#define DF_S_OK                     0x00
#define DF_S_ADDITIONAL_FRAME       0xAF
#define DF_S_SIGNATURE              0x90

// largest chunk of payload sent in one frame, the ISO 14443-4 layer below us
// may fragment further
#define NXPSC_TX_FRAME_MAX          54

// internal communication modes, the public enum has no EncryptedPlain
typedef enum {
    MODE_PLAIN = 0,
    MODE_MAC,
    MODE_ENC,
    MODE_ENC_PADDED,
    // ChangeKey style, payload is enciphered but the card has no session yet
    MODE_ENC_PLAIN,
} nxpsc_mode_t;

struct nxpsc_card {
    nxpsc_transport_t transport;

    nxpsc_cmdset_t cmdset;
    nxpsc_channel_t channel;        // NXPSC_CHAN_AUTO means no secure channel
    nxpsc_commmode_t default_comm;
    bool authenticated;
    // set when the PICC aborted secure messaging under us, cleared by the next
    // authentication or by an explicit nxpsc_reset_channel()
    bool session_lost;

    nxpsc_mode_t mode;              // mode of the command being processed
    nxpsc_keytype_t key_type;
    uint8_t key[NXPSC_MAX_KEY_SIZE];
    uint8_t key_no;

    uint8_t iv[NXPSC_MAX_BLOCK];
    uint8_t session_enc[NXPSC_MAX_KEY_SIZE];
    uint8_t session_mac[NXPSC_MAX_KEY_SIZE];

    uint8_t ti[4];
    uint16_t cmd_ctr;
    uint16_t plus_r_ctr;            // MIFARE Plus SL3 read counter
    uint16_t plus_w_ctr;            // MIFARE Plus SL3 write counter
    uint8_t last_cmd;
    bool last_request_zero_len;
    uint8_t last_status;
    bool mac_mismatch;              // set when a received MAC did not verify

    uint32_t selected_aid;
    uint8_t uid[10];
    size_t uid_len;

    bool iso_chaining;              // use the 0xAD / 0x8D style opcodes
    bool version_read;
    nxpsc_version_t version;
    nxpsc_cardtype_t type;
};

size_t nxpsc_mac_length(const nxpsc_card_t *card);
size_t nxpsc_padded_len(size_t len, size_t block);

// raw exchange, no secure channel. resp excludes the status byte
int nxpsc_raw_exchange(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                       uint8_t *status, uint8_t *resp, size_t cap, size_t *resp_len);
// variant for callers that must see authentication handshake 0xAF statuses
int nxpsc_raw_exchange_ex(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                          uint8_t *status, uint8_t *resp, size_t cap, size_t *resp_len,
                          bool follow_af);
// full exchange through the active secure channel
int nxpsc_exchange(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                   nxpsc_mode_t tx_mode, nxpsc_mode_t rx_mode,
                   uint8_t *resp, size_t cap, size_t *resp_len);
// ISO 7816-4 exchange, used by the ISO command set and MIFARE Plus
int nxpsc_iso_exchange(nxpsc_card_t *card, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                       const uint8_t *data, size_t len, bool le_present, size_t le,
                       uint8_t *resp, size_t cap, size_t *resp_len, uint16_t *sw);

int nxpsc_channel_encode(nxpsc_card_t *card, uint8_t cmd, const uint8_t *src, size_t src_len,
                         uint8_t *dst, size_t cap, size_t *dst_len);
int nxpsc_channel_decode(nxpsc_card_t *card, const uint8_t *src, size_t src_len, uint8_t status,
                         uint8_t *dst, size_t cap, size_t *dst_len);

nxpsc_mode_t nxpsc_mode_from_public(nxpsc_commmode_t comm);

// true for the statuses that make the PICC drop the secure messaging session
bool nxpsc_status_ends_session(uint8_t status);

// EV2 / LRP session helpers, shared with the self test
void nxpsc_ev2_fill_iv(nxpsc_card_t *card, bool for_command, uint8_t *iv);
int nxpsc_ev2_cmac(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                   uint8_t *mac8);
// CRC search used when decoding a deciphered response
size_t nxpsc_search_crc_pos(const uint8_t *data, size_t len, uint8_t status, uint8_t crc_len);

#endif // NXPSC_INTERNAL_H__

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
// libnxpsc - mock card used by the protocol tests. it answers GetVersion with
// the identification bytes of a chosen card family and records what the
// library transmitted, so the tests can assert on the framing
//-----------------------------------------------------------------------------

#include "mockcard.h"

#include <string.h>

typedef struct {
    nxpsc_cardtype_t type;
    uint8_t hw_type;
    uint8_t hw_major;
    uint8_t hw_minor;
    uint8_t storage;
} family_t;

static const family_t families[] = {
    {DESFIRE_MF3ICD40, 0x01, 0x00, 0x02, 0x18},
    {DESFIRE_EV1,      0x01, 0x01, 0x00, 0x18},
    {DESFIRE_EV2,      0x01, 0x12, 0x00, 0x18},
    {DESFIRE_EV2_XL,   0x01, 0x22, 0x00, 0x1A},
    {DESFIRE_EV3,      0x01, 0x33, 0x00, 0x18},
    {DESFIRE_LIGHT,    0x08, 0x30, 0x00, 0x13},
    {PLUS_EV1,         0x02, 0x11, 0x00, 0x18},
    {PLUS_EV2,         0x02, 0x22, 0x00, 0x18},
    {NTAG413DNA,       0x04, 0x10, 0x00, 0x0F},
    {NTAG424,          0x04, 0x30, 0x00, 0x11},
    {DUOX,             0x01, 0xA0, 0x00, 0x1A},
};

size_t mock_family_count(void) {
    return sizeof(families) / sizeof(families[0]);
}

nxpsc_cardtype_t mock_family_type(size_t index) {
    return families[index].type;
}

static const family_t *find_family(nxpsc_cardtype_t type) {
    for (size_t i = 0; i < mock_family_count(); i++) {
        if (families[i].type == type) {
            return &families[i];
        }
    }
    return &families[1];
}

void mock_init(mock_card_t *mock, nxpsc_cardtype_t type) {
    memset(mock, 0, sizeof(*mock));
    mock->type = type;

    static const uint8_t uid[7] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(mock->uid, uid, sizeof(uid));
}

// GetVersion answers in three frames, the first two ask for continuation
static int version_frame(const mock_card_t *mock, uint8_t *rx, size_t cap, size_t *rx_len) {
    const family_t *fam = find_family(mock->type);

    if (cap < 9) {
        return NXPSC_E_LENGTH;
    }

    switch (mock->version_step) {
        case 0:
            rx[0] = 0xAF;
            rx[1] = 0x04;               // NXP
            rx[2] = fam->hw_type;
            rx[3] = 0x01;               // subtype
            rx[4] = fam->hw_major;
            rx[5] = fam->hw_minor;
            rx[6] = fam->storage;
            rx[7] = 0x05;               // protocol
            *rx_len = 8;
            return NXPSC_OK;

        case 1:
            rx[0] = 0xAF;
            rx[1] = 0x04;
            rx[2] = fam->hw_type;
            rx[3] = 0x01;
            rx[4] = fam->hw_major;
            rx[5] = fam->hw_minor;
            rx[6] = fam->storage;
            rx[7] = 0x05;
            *rx_len = 8;
            return NXPSC_OK;

        default:
            break;
    }

    if (cap < 15) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0x00;
    memcpy(rx + 1, mock->uid, 7);
    memset(rx + 8, 0xAA, 5);            // batch number
    rx[13] = 0x01;                      // production week
    rx[14] = 0x18;                      // production year
    *rx_len = 15;
    return NXPSC_OK;
}

static bool is_plus(const mock_card_t *mock) {
    return (mock->type == PLUS_EV1) || (mock->type == PLUS_EV2);
}

// MIFARE Plus answers 0x90 on success, the SL3 opcodes overlap with the
// DESFire ones so the family decides which handler runs
static int plus_frame(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)tx_len;

    switch (tx[0]) {
        case 0x70:                      // AuthenticateFirst
        case 0x76: {                    // AuthenticateNonFirst
            if (cap < 17) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x90;
            memset(rx + 1, 0x5A, 16);   // enciphered RndB, the tests do not verify it
            *rx_len = 17;
            return NXPSC_OK;
        }

        default:
            break;
    }

    if (cap < 1) {
        return NXPSC_E_LENGTH;
    }

    mock->plus_last_op = tx[0];
    rx[0] = 0x90;
    *rx_len = 1;
    return NXPSC_OK;
}

static int native_frame(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t cap, size_t *rx_len);

int mock_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t cap, size_t *rx_len) {
    mock_card_t *mock = (mock_card_t *)ctx;

    if (tx_len == 0 || cap < 1) {
        return NXPSC_E_PARAM;
    }

    if (mock->tx_count < MOCK_MAX_FRAMES) {
        size_t n = (tx_len > MOCK_FRAME_SIZE) ? MOCK_FRAME_SIZE : tx_len;
        memcpy(mock->tx[mock->tx_count], tx, n);
        mock->tx_len[mock->tx_count] = n;
    }
    mock->tx_count++;

    return native_frame(mock, tx, tx_len, rx, cap, rx_len);
}

static int native_frame(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t cap, size_t *rx_len) {
    if (is_plus(mock) && tx[0] != 0x60 && tx[0] != 0xAF && tx[0] != 0x00) {
        return plus_frame(mock, tx, tx_len, rx, cap, rx_len);
    }

    // ISO 7816-4 wrapped frame, answer with a plain 0x9000
    if (tx[0] == 0x00 || tx[0] == 0x90) {
        if (tx[0] == 0x90 && tx_len >= 2) {
            // wrapped native command, unwrap and fall through
            uint8_t inner[64] = {0};
            size_t inner_len = 0;

            inner[0] = tx[1];
            if (tx_len > 6) {
                inner_len = tx_len - 6;
                if (inner_len > sizeof(inner) - 1) {
                    inner_len = sizeof(inner) - 1;
                }
                memcpy(inner + 1, tx + 5, inner_len);
            }

            uint8_t native[MOCK_FRAME_SIZE] = {0};
            size_t native_len = 0;
            int rc = native_frame(mock, inner, inner_len + 1, native, sizeof(native),
                                  &native_len);
            if (rc != NXPSC_OK || native_len < 1) {
                return rc;
            }
            if (cap < native_len + 1) {
                return NXPSC_E_LENGTH;
            }

            memcpy(rx, native + 1, native_len - 1);
            rx[native_len - 1] = 0x91;
            rx[native_len] = native[0];
            *rx_len = native_len + 1;
            return NXPSC_OK;
        }

        if (cap < 2) {
            return NXPSC_E_LENGTH;
        }
        rx[0] = 0x90;
        rx[1] = 0x00;
        *rx_len = 2;
        return NXPSC_OK;
    }

    switch (tx[0]) {
        case 0x60:                      // GetVersion
            mock->version_step = 0;
            return version_frame(mock, rx, cap, rx_len);

        case 0xAF:                      // additional frame
            mock->version_step++;
            return version_frame(mock, rx, cap, rx_len);

        case 0x5A:                      // SelectApplication
            if (tx_len >= 4) {
                mock->selected_aid = (uint32_t)tx[1] | ((uint32_t)tx[2] << 8) |
                                     ((uint32_t)tx[3] << 16);
            }
            rx[0] = 0x00;
            *rx_len = 1;
            return NXPSC_OK;

        case 0x6A:                      // GetApplicationIDs
            if (cap < 7) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x01;
            rx[2] = 0x02;
            rx[3] = 0x03;
            rx[4] = 0x11;
            rx[5] = 0x22;
            rx[6] = 0x33;
            *rx_len = 7;
            return NXPSC_OK;

        case 0x6F:                      // GetFileIDs
            if (cap < 4) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x00;
            rx[2] = 0x01;
            rx[3] = 0x02;
            *rx_len = 4;
            return NXPSC_OK;

        case 0xF5:                      // GetFileSettings, standard data file
            if (cap < 8) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x00;               // std data file
            rx[2] = 0x00;               // plain
            rx[3] = 0xEE;               // access rights
            rx[4] = 0x00;
            rx[5] = 0x20;               // size 0x20
            rx[6] = 0x00;
            rx[7] = 0x00;
            *rx_len = 8;
            return NXPSC_OK;

        case 0x6C:                      // GetValue
            if (cap < 5) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x39;
            rx[2] = 0x30;
            rx[3] = 0x00;
            rx[4] = 0x00;
            *rx_len = 5;
            return NXPSC_OK;

        case 0xBD: {                    // ReadData
            uint32_t length = 0;
            if (tx_len >= 8) {
                length = (uint32_t)tx[5] | ((uint32_t)tx[6] << 8) | ((uint32_t)tx[7] << 16);
            }
            if (length == 0 || length > cap - 1) {
                length = (cap > 17) ? 16 : 1;
            }

            rx[0] = 0x00;
            for (uint32_t i = 0; i < length; i++) {
                rx[1 + i] = (uint8_t)i;
            }
            *rx_len = length + 1;
            return NXPSC_OK;
        }

        case 0x6E:                      // GetFreeMemory
            if (cap < 4) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x00;
            rx[2] = 0x08;
            rx[3] = 0x00;
            *rx_len = 4;
            return NXPSC_OK;

        case 0x51:                      // GetCardUID, only valid authenticated
            rx[0] = 0xAE;
            *rx_len = 1;
            return NXPSC_OK;

        default:
            break;
    }

    // everything else acknowledges without data
    rx[0] = 0x00;
    *rx_len = 1;
    return NXPSC_OK;
}

int mock_get_uid(void *ctx, uint8_t *uid, size_t cap, size_t *len) {
    mock_card_t *mock = (mock_card_t *)ctx;

    if (cap < sizeof(mock->uid)) {
        return NXPSC_E_LENGTH;
    }
    memcpy(uid, mock->uid, sizeof(mock->uid));
    *len = sizeof(mock->uid);
    return NXPSC_OK;
}

void mock_transport(mock_card_t *mock, nxpsc_transport_t *transport) {
    memset(transport, 0, sizeof(*transport));
    transport->ctx = mock;
    transport->transceive = mock_transceive;
    transport->get_uid = mock_get_uid;
}

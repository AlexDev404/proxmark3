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
// libnxpsc - mock card transport for the protocol tests
//-----------------------------------------------------------------------------

#ifndef NXPSC_MOCKCARD_H__
#define NXPSC_MOCKCARD_H__

#include "nxpsc/nxpsc.h"

#define MOCK_MAX_FRAMES     32
#define MOCK_FRAME_SIZE     128

typedef struct {
    nxpsc_cardtype_t type;
    uint8_t uid[7];
    uint32_t selected_aid;
    int version_step;
    uint8_t plus_last_op;

    uint8_t tx[MOCK_MAX_FRAMES][MOCK_FRAME_SIZE];
    size_t tx_len[MOCK_MAX_FRAMES];
    size_t tx_count;
} mock_card_t;

size_t mock_family_count(void);
nxpsc_cardtype_t mock_family_type(size_t index);

void mock_init(mock_card_t *mock, nxpsc_cardtype_t type);
void mock_transport(mock_card_t *mock, nxpsc_transport_t *transport);

int mock_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t cap, size_t *rx_len);
int mock_get_uid(void *ctx, uint8_t *uid, size_t cap, size_t *len);

#endif // NXPSC_MOCKCARD_H__

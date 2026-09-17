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
// libnxpsc - example transport
//
// Stand in for a real reader backend. It answers GetVersion with a DESFire EV2
// answer and acknowledges everything else, so the example can run with no
// hardware attached. Replace transceive() with one of
//
//   libnfc   nfc_initiator_transceive_bytes()
//   PC/SC    SCardTransmit() with the T=1 protocol
//   Android  IsoDep.transceive() through JNI
//   Node     an N-API wrapper around any of the above
//   MCU      your ISO 14443-4 block exchange
//
// The only contract is that tx/rx carry the INF field, i.e. no framing, no CRC
// and no chaining at the ISO 14443-4 level.
//-----------------------------------------------------------------------------

#include "loopback.h"

#include <string.h>
#include <stdio.h>

static const uint8_t s_version[3][16] = {
    { 0x04, 0x01, 0x01, 0x12, 0x00, 0x1A, 0x05 },
    { 0x04, 0x01, 0x01, 0x12, 0x00, 0x1A, 0x05 },
    { 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0xC1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x33, 0x25 },
};
static const size_t s_version_len[3] = { 7, 7, 15 };

static void dump(const char *tag, const uint8_t *data, size_t len) {
    printf("%s", tag);
    for (size_t i = 0; i < len; i++) {
        printf(" %02X", data[i]);
    }
    printf("\n");
}

int loopback_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t cap, size_t *rx_len) {

    loopback_t *lb = (loopback_t *)ctx;

    if (lb == NULL || tx == NULL || rx == NULL || rx_len == NULL || tx_len == 0) {
        return NXPSC_E_PARAM;
    }

    if (lb->verbose) {
        dump("  ->", tx, tx_len);
    }

    uint8_t cmd = tx[0];
    size_t len = 0;

    if (cmd == 0x60 || cmd == 0xAF) {
        if (cmd == 0x60) {
            lb->version_step = 0;
        }
        if (lb->version_step > 2) {
            lb->version_step = 2;
        }

        len = s_version_len[lb->version_step];
        if (cap < len + 1) {
            return NXPSC_E_LENGTH;
        }

        rx[0] = (lb->version_step < 2) ? 0xAF : 0x00;
        memcpy(rx + 1, s_version[lb->version_step], len);
        lb->version_step++;
        *rx_len = len + 1;

    } else {
        if (cap < 1) {
            return NXPSC_E_LENGTH;
        }
        rx[0] = 0x00;
        *rx_len = 1;
    }

    if (lb->verbose) {
        dump("  <-", rx, *rx_len);
    }
    return NXPSC_OK;
}

int loopback_get_uid(void *ctx, uint8_t *uid, size_t cap, size_t *len) {
    (void)ctx;
    static const uint8_t demo[7] = { 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22 };

    if (uid == NULL || len == NULL || cap < sizeof(demo)) {
        return NXPSC_E_PARAM;
    }

    memcpy(uid, demo, sizeof(demo));
    *len = sizeof(demo);
    return NXPSC_OK;
}

void loopback_transport(loopback_t *lb, nxpsc_transport_t *transport) {
    memset(lb, 0, sizeof(*lb));
    lb->verbose = true;

    memset(transport, 0, sizeof(*transport));
    transport->ctx = lb;
    transport->transceive = loopback_transceive;
    transport->get_uid = loopback_get_uid;
}

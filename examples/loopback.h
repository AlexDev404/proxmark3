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
//-----------------------------------------------------------------------------

#ifndef NXPSC_EXAMPLE_LOOPBACK_H__
#define NXPSC_EXAMPLE_LOOPBACK_H__

#include "nxpsc/nxpsc.h"

typedef struct {
    int version_step;
    bool verbose;
} loopback_t;

void loopback_transport(loopback_t *lb, nxpsc_transport_t *transport);

int loopback_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t cap, size_t *rx_len);
int loopback_get_uid(void *ctx, uint8_t *uid, size_t cap, size_t *len);

#endif // NXPSC_EXAMPLE_LOOPBACK_H__

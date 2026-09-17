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
// libnxpsc - reclaim NV memory on a DESFire with FormatPICC, over PC/SC
//
// DESFire frees the AID when an application is deleted but not the non volatile
// memory behind it, so a card that is repeatedly provisioned and wiped keeps
// losing free memory until it can no longer create anything. FormatPICC is the
// only command that gives that memory back.
//
// Unlike the other examples this one talks to a real reader rather than the
// loopback transport, so it doubles as the shortest complete PC/SC transport
// worth copying.
//
//   nxpsc_reclaim                  report the card, nothing is changed
//   nxpsc_reclaim --format         authenticate and FormatPICC
//   nxpsc_reclaim --key <hex>      PICC master key, default is the factory zeros
//
// FormatPICC deletes every application and every file on the card. It is
// refused unless --format is given, and the PICC master key itself is never
// touched, so a formatted card keeps whatever key it had.
//-----------------------------------------------------------------------------

#include "nxpsc/nxpsc.h"

#ifdef _WIN32
#include <winscard.h>
#else
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
// the ANSI suffixed names are a Windows spelling, pcsclite is char based
#define SCardListReadersA   SCardListReaders
#define SCardConnectA       SCardConnect
#endif

#include <stdio.h>
#include <string.h>

typedef struct {
    SCARDHANDLE handle;
} pcsc_t;

//-----------------------------------------------------------------------------
// transport
//-----------------------------------------------------------------------------
static int pcsc_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                           uint8_t *rx, size_t cap, size_t *rx_len) {
    pcsc_t *pcsc = (pcsc_t *)ctx;
    DWORD received = (DWORD)cap;

    LONG rc = SCardTransmit(pcsc->handle, SCARD_PCI_T1, tx, (DWORD)tx_len,
                            NULL, rx, &received);
    if (rc != SCARD_S_SUCCESS) {
        return NXPSC_E_TRANSPORT;
    }

    *rx_len = received;
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// helpers
//-----------------------------------------------------------------------------
static void step(const char *what, int rc, nxpsc_card_t *card) {
    if (rc == NXPSC_OK) {
        printf("  ok    %s\n", what);
        return;
    }

    printf("  FAIL  %s: %s", what, nxpsc_strerror(rc));
    if (rc == NXPSC_E_CARD && card != NULL) {
        printf(" (status 0x%02X: %s)", nxpsc_last_status(card),
               nxpsc_status_str(nxpsc_last_status(card)));
    }
    printf("\n");
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex_key(const char *text, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(text);

    if (n == 0 || (n % 2) != 0 || (n / 2) > cap) {
        return NXPSC_E_PARAM;
    }

    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_nibble(text[i]);
        int lo = hex_nibble(text[i + 1]);
        if (hi < 0 || lo < 0) {
            return NXPSC_E_PARAM;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }

    *len = n / 2;
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
int main(int argc, char **argv) {
    bool do_format = false;
    nxpsc_key_t picc;

    // the factory PICC master key, 2TDEA with every byte zero
    memset(&picc, 0, sizeof(picc));
    picc.type = NXPSC_KEY_2K3DES;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0) {
            do_format = true;
        } else if (strcmp(argv[i], "--key") == 0 && (i + 1) < argc) {
            size_t key_len = 0;
            if (parse_hex_key(argv[++i], picc.data, sizeof(picc.data), &key_len) != NXPSC_OK) {
                printf("--key wants an even number of hex digits\n");
                return 1;
            }
            // 8 bytes is single DES, 16 is 2TDEA, 24 is 3TDEA
            picc.type = (key_len == 8) ? NXPSC_KEY_DES
                        : (key_len == 24) ? NXPSC_KEY_3K3DES : NXPSC_KEY_2K3DES;
        } else {
            printf("usage: %s [--format] [--key <hex>]\n", argv[0]);
            return 1;
        }
    }

    // the crypto is self checking, refuse to touch a card if a vector fails
    if (nxpsc_selftest(false) != NXPSC_OK) {
        printf("crypto self test failed\n");
        return 1;
    }

    SCARDCONTEXT context;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context) != SCARD_S_SUCCESS) {
        printf("no PC/SC context\n");
        return 1;
    }

    char readers[1024] = {0};
    DWORD readers_len = sizeof(readers);
    if (SCardListReadersA(context, NULL, readers, &readers_len) != SCARD_S_SUCCESS) {
        printf("no reader\n");
        SCardReleaseContext(context);
        return 1;
    }

    pcsc_t pcsc;
    DWORD protocol = 0;
    memset(&pcsc, 0, sizeof(pcsc));

    // the list is a multi string, the first entry is the reader we use
    if (SCardConnectA(context, readers, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
                      &pcsc.handle, &protocol) != SCARD_S_SUCCESS) {
        printf("no card on %s\n", readers);
        SCardReleaseContext(context);
        return 1;
    }
    printf("reader: %s\n", readers);

    nxpsc_transport_t transport;
    memset(&transport, 0, sizeof(transport));
    transport.ctx = &pcsc;
    transport.transceive = pcsc_transceive;

    nxpsc_card_t *card = NULL;
    int rc = nxpsc_open(&transport, &card);
    if (rc != NXPSC_OK) {
        printf("open: %s\n", nxpsc_strerror(rc));
        SCardDisconnect(pcsc.handle, SCARD_LEAVE_CARD);
        SCardReleaseContext(context);
        return 1;
    }

    // PC/SC cannot send raw native frames, wrap them in ISO 7816-4 APDUs
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    int status = 0;
    nxpsc_version_t version;
    rc = nxpsc_get_version(card, &version);
    step("GetVersion", rc, card);
    if (rc != NXPSC_OK) {
        status = 1;
        goto done;
    }

    printf("  card  %s\n", nxpsc_cardtype_str(nxpsc_card_type(card)));
    printf("  uid   ");
    for (size_t i = 0; i < sizeof(version.uid); i++) {
        printf("%02X", version.uid[i]);
    }
    printf("\n");

    uint32_t before = 0;
    uint32_t after = 0;
    if (nxpsc_get_free_memory(card, &before) == NXPSC_OK) {
        printf("  free  %u bytes\n", before);
    }

    rc = nxpsc_select_application(card, 0x000000);
    step("SelectApplication PICC", rc, card);
    if (rc != NXPSC_OK) {
        status = 1;
        goto done;
    }

    uint32_t aids[NXPSC_MAX_APPS];
    size_t count = 0;
    if (nxpsc_get_application_ids(card, aids, NXPSC_MAX_APPS, &count) == NXPSC_OK) {
        printf("  apps  %zu present\n", count);
        for (size_t i = 0; i < count; i++) {
            printf("        aid %06X\n", aids[i]);
        }
    }

    if (do_format == false) {
        printf("\nreporting only. FormatPICC deletes every application and file\n"
               "on this card, pass --format to go ahead\n");
        goto done;
    }

    rc = nxpsc_authenticate(card, 0, &picc, NXPSC_CHAN_AUTO);
    step("Authenticate PICC master key", rc, card);
    if (rc != NXPSC_OK) {
        printf("\nthat is not this card's PICC master key, nothing was changed\n");
        status = 1;
        goto done;
    }

    rc = nxpsc_format_picc(card);
    step("FormatPICC", rc, card);
    if (rc != NXPSC_OK) {
        status = 1;
        goto done;
    }

    if (nxpsc_get_free_memory(card, &after) == NXPSC_OK) {
        printf("  free  %u bytes after (+%d)\n", after, (int)after - (int)before);
    }

done:
    nxpsc_close(card);
    SCardDisconnect(pcsc.handle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return status;
}

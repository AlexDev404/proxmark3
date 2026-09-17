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
// libnxpsc - ticketing style personalisation walkthrough
//
// Shows the call sequence an issuing station would use. It runs against the
// example loopback transport, which acknowledges commands but does no crypto,
// so the authentication steps are expected to fail here. Point the transport
// at a real reader and the same code personalises a card.
//-----------------------------------------------------------------------------

#include "loopback.h"

#include <stdio.h>
#include <string.h>

#define TICKET_AID      0xF51234
#define TICKET_FILE     0x01

static void step(const char *what, int rc) {
    printf("%-42s %s\n", what, (rc == NXPSC_OK) ? "ok" : nxpsc_strerror(rc));
}

int main(void) {

    // the crypto is self checking, refuse to touch a card if a vector fails
    if (nxpsc_selftest(false) != NXPSC_OK) {
        printf("crypto self test failed\n");
        return 1;
    }

    loopback_t lb;
    nxpsc_transport_t transport;
    loopback_transport(&lb, &transport);
    lb.verbose = false;

    nxpsc_card_t *card = NULL;
    int rc = nxpsc_open(&transport, &card);
    if (rc != NXPSC_OK) {
        printf("open: %s\n", nxpsc_strerror(rc));
        return 1;
    }

    nxpsc_version_t version;
    rc = nxpsc_get_version(card, &version);
    step("GetVersion", rc);

    nxpsc_cardtype_t type = NXP_UNKNOWN;
    nxpsc_identify(card, &type);
    printf("%-42s %s\n", "identified", nxpsc_cardtype_str(type));

    // 1. authenticate with the factory PICC master key, all zeroes single DES
    nxpsc_key_t factory = { .type = NXPSC_KEY_DES };
    rc = nxpsc_select_application(card, 0x000000);
    step("SelectApplication 000000", rc);
    rc = nxpsc_authenticate(card, 0x00, &factory, NXPSC_CHAN_AUTO);
    step("Authenticate PICC master key", rc);

    // 2. replace the factory key with an AES issuer key
    nxpsc_key_t issuer = {
        .type = NXPSC_KEY_AES128,
        .version = 0x01,
        .data = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        },
    };
    rc = nxpsc_change_key(card, 0x00, &factory, &issuer);
    step("ChangeKey PICC master key to AES", rc);

    // 3. derive the per card application key with AN10922
    uint8_t uid[10] = {0};
    size_t uid_len = 0;
    nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len);

    uint8_t div_input[32];
    size_t div_len = 0;
    memcpy(div_input, uid, uid_len);
    div_len += uid_len;
    div_input[div_len++] = (uint8_t)(TICKET_AID & 0xFF);
    div_input[div_len++] = (uint8_t)((TICKET_AID >> 8) & 0xFF);
    div_input[div_len++] = (uint8_t)((TICKET_AID >> 16) & 0xFF);
    memcpy(div_input + div_len, "NXPSC-DEMO", 10);
    div_len += 10;

    nxpsc_key_t app_key;
    rc = nxpsc_diversify_an10922(&issuer, div_input, div_len, &app_key);
    step("AN10922 diversify application key", rc);

    // 4. create the ticketing application and its files
    rc = nxpsc_create_application(card, TICKET_AID, 0x0F, 3, NXPSC_KEY_AES128);
    step("CreateApplication F51234", rc);

    rc = nxpsc_select_application(card, TICKET_AID);
    step("SelectApplication F51234", rc);

    rc = nxpsc_authenticate(card, 0x00, &app_key, NXPSC_CHAN_AUTO);
    step("Authenticate application master key", rc);

    nxpsc_access_t access = { .read = 0x01, .write = 0x02, .read_write = 0x02, .change = 0x00 };
    rc = nxpsc_create_std_file(card, TICKET_FILE, 0x0001, NXPSC_COMM_FULL, &access, 32);
    step("CreateStdDataFile 01", rc);

    nxpsc_access_t purse = { .read = 0x01, .write = 0x02, .read_write = 0x02, .change = 0x00 };
    rc = nxpsc_create_value_file(card, 0x02, NXPSC_COMM_FULL, &purse, 0, 100000, 0, true);
    step("CreateValueFile 02 closed loop purse", rc);

    // 5. write the card holder record and commit
    const uint8_t profile[32] = { 'T', 'I', 'C', 'K', 'E', 'T', '0', '1' };
    rc = nxpsc_write_data(card, TICKET_FILE, 0, profile, sizeof(profile), NXPSC_COMM_FULL);
    step("WriteData 01", rc);
    rc = nxpsc_commit_transaction(card);
    step("CommitTransaction", rc);

    nxpsc_close(card);
    return 0;
}

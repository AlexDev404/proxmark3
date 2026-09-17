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
// libnxpsc - protocol level tests. every supported card family is exercised
// against the mock card so the CI can tell which family regressed
//-----------------------------------------------------------------------------

#include "mockcard.h"
#include "nxpsc_crypto.h"
#include "nxpsc_internal.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, bool ok) {
    printf("%-44s %s\n", name, ok ? "ok" : "FAIL");
    if (ok == false) {
        failures++;
    }
}

typedef struct {
    uint8_t key[16];
    uint8_t rnd_b[16];
    uint8_t ti[4];
    bool corrupt_final;
} plus_auth_ctx_t;

static int fixed_rng(void *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(0x10 + i);
    }
    return NXPSC_OK;
}

static int plus_auth_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t cap, size_t *rx_len) {
    plus_auth_ctx_t *auth = (plus_auth_ctx_t *)ctx;

    if (tx_len == 0 || cap < 1) {
        return NXPSC_E_PARAM;
    }

    if (tx[0] == 0x70) {
        if (cap < 17) {
            return NXPSC_E_LENGTH;
        }

        uint8_t iv[16] = {0};
        rx[0] = 0x90;
        if (nxpsc_cbc_crypt(NXPSC_KEY_AES128, auth->key, iv, auth->rnd_b, 16, rx + 1, true) != NXPSC_OK) {
            return NXPSC_E_CRYPTO;
        }
        *rx_len = 17;
        return NXPSC_OK;
    }

    if (tx[0] == 0xAF) {
        if (tx_len != 33 || cap < 33) {
            return NXPSC_E_LENGTH;
        }

        uint8_t iv[16] = {0};
        uint8_t plain[32] = {0};
        if (nxpsc_cbc_crypt(NXPSC_KEY_AES128, auth->key, iv, tx + 1, 32, plain, false) != NXPSC_OK) {
            return NXPSC_E_CRYPTO;
        }

        uint8_t expect_rot_b[16] = {0};
        memcpy(expect_rot_b, auth->rnd_b + 1, 15);
        expect_rot_b[15] = auth->rnd_b[0];
        if (memcmp(plain + 16, expect_rot_b, 16) != 0) {
            return NXPSC_E_AUTH;
        }

        uint8_t reply[32] = {0};
        memcpy(reply, auth->ti, sizeof(auth->ti));
        memcpy(reply + 4, plain + 1, 15);
        reply[19] = plain[0];

        memset(iv, 0, sizeof(iv));
        rx[0] = 0x90;
        if (nxpsc_cbc_crypt(NXPSC_KEY_AES128, auth->key, iv, reply, 32, rx + 1, true) != NXPSC_OK) {
            return NXPSC_E_CRYPTO;
        }
        if (auth->corrupt_final) {
            rx[1] ^= 0x80;
        }
        *rx_len = 33;
        return NXPSC_OK;
    }

    return NXPSC_E_PARAM;
}

typedef struct {
    uint8_t payload[16];
    size_t payload_len;
} plus_read_ctx_t;

static int plus_read_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t cap, size_t *rx_len) {
    plus_read_ctx_t *read = (plus_read_ctx_t *)ctx;
    (void)tx;
    (void)tx_len;

    if (cap < read->payload_len + 1) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0x90;
    memcpy(rx + 1, read->payload, read->payload_len);
    *rx_len = read->payload_len + 1;
    return NXPSC_OK;
}

// identification must work for every card family the library claims to support
static void test_identify(void) {
    for (size_t i = 0; i < mock_family_count(); i++) {
        nxpsc_cardtype_t want = mock_family_type(i);

        mock_card_t mock;
        nxpsc_transport_t transport;
        nxpsc_card_t *card = NULL;

        mock_init(&mock, want);
        mock_transport(&mock, &transport);

        bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

        nxpsc_cardtype_t got = NXP_UNKNOWN;
        ok = ok && (nxpsc_identify(card, &got) == NXPSC_OK);
        ok = ok && (got == want);
        // GetVersion is three frames, 0x60 followed by two 0xAF
        ok = ok && (mock.tx_count == 3);
        ok = ok && (mock.tx[0][0] == 0x60);
        ok = ok && (mock.tx[1][0] == 0xAF);

        char name[64];
        snprintf(name, sizeof(name), "identify %s", nxpsc_cardtype_str(want));
        check(name, ok);

        nxpsc_close(card);
    }
}

static void test_version_fields(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    nxpsc_version_t version;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_get_version(card, &version) == NXPSC_OK);
    ok = ok && (version.hw_vendor == 0x04);
    ok = ok && (version.hw_type == 0x01);
    ok = ok && (version.hw_major == 0x33);
    ok = ok && (version.uid[0] == 0x04);
    ok = ok && (version.year == 0x18);

    check("GetVersion decoding", ok);
    nxpsc_close(card);
}

static void test_native_framing(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_select_application(card, 0x030201) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    ok = ok && (mock.tx_len[0] == 4);
    ok = ok && (mock.tx[0][0] == 0x5A);
    // the AID travels little endian
    ok = ok && (mock.tx[0][1] == 0x01) && (mock.tx[0][2] == 0x02) && (mock.tx[0][3] == 0x03);
    ok = ok && (nxpsc_selected_aid(card) == 0x030201);

    check("native SelectApplication framing", ok);
    nxpsc_close(card);
}

static void test_iso_wrapping(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    ok = ok && (nxpsc_select_application(card, 0x030201) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    // CLA 0x90, INS is the native command, P1 P2 zero, Lc, data, Le
    ok = ok && (mock.tx[0][0] == 0x90);
    ok = ok && (mock.tx[0][1] == 0x5A);
    ok = ok && (mock.tx[0][2] == 0x00) && (mock.tx[0][3] == 0x00);
    ok = ok && (mock.tx[0][4] == 0x03);
    ok = ok && (mock.tx_len[0] == 9);
    ok = ok && (mock.tx[0][8] == 0x00);

    check("ISO wrapped native framing", ok);
    nxpsc_close(card);
}

static void test_iso_wrapping_zero_data(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    nxpsc_version_t version;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    ok = ok && (nxpsc_get_version(card, &version) == NXPSC_OK);
    ok = ok && (mock.tx_count == 3);
    ok = ok && (mock.tx_len[0] == 5);
    ok = ok && (mock.tx[0][0] == 0x90) && (mock.tx[0][1] == 0x60);
    ok = ok && (mock.tx[0][2] == 0x00) && (mock.tx[0][3] == 0x00) && (mock.tx[0][4] == 0x00);
    ok = ok && (mock.tx_len[1] == 5) && (mock.tx_len[2] == 5);
    ok = ok && (mock.tx[1][0] == 0x90) && (mock.tx[1][1] == 0xAF);
    ok = ok && (mock.tx[2][0] == 0x90) && (mock.tx[2][1] == 0xAF);
    ok = ok && (mock.tx[1][2] == 0x00) && (mock.tx[1][3] == 0x00) && (mock.tx[1][4] == 0x00);
    ok = ok && (mock.tx[2][2] == 0x00) && (mock.tx[2][3] == 0x00) && (mock.tx[2][4] == 0x00);

    check("ISO wrapped zero-data framing", ok);
    nxpsc_close(card);
}

static void test_file_settings(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    nxpsc_file_settings_t settings;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_get_file_settings(card, 0x01, &settings) == NXPSC_OK);
    ok = ok && (settings.type == NXPSC_FILE_STD);
    ok = ok && (settings.comm == NXPSC_COMM_PLAIN);
    ok = ok && (settings.size == 0x20);
    // access rights 0x00EE, read and write are free, the rest denied
    ok = ok && (settings.access.read == 0x00);
    ok = ok && (settings.access.change == 0x0E);

    check("GetFileSettings decoding", ok);
    nxpsc_close(card);
}

static void test_create_file_framing(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    nxpsc_access_t access = {.read = 0x00, .write = 0x01, .read_write = 0x02, .change = 0x03};

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x02, 0, NXPSC_COMM_FULL, &access, 0x100)
                == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    ok = ok && (mock.tx[0][0] == 0xCD);
    ok = ok && (mock.tx[0][1] == 0x02);
    ok = ok && (mock.tx[0][2] == 0x03);      // fully enciphered
    ok = ok && (mock.tx[0][3] == 0x23);      // access rights low byte
    ok = ok && (mock.tx[0][4] == 0x01);      // access rights high byte
    ok = ok && (mock.tx[0][5] == 0x00) && (mock.tx[0][6] == 0x01) && (mock.tx[0][7] == 0x00);
    ok = ok && (mock.tx_len[0] == 8);

    check("CreateStdDataFile framing", ok);
    nxpsc_close(card);
}

static void test_value_and_data(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    int32_t value = 0;
    ok = ok && (nxpsc_get_value(card, 0x01, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 0x3039);

    uint8_t buf[64] = {0};
    size_t len = 0;
    ok = ok && (nxpsc_read_data(card, 0x01, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len)
                == NXPSC_OK);
    ok = ok && (len == 16) && (buf[0] == 0x00) && (buf[15] == 0x0F);

    check("value and data file access", ok);
    nxpsc_close(card);
}

static void test_access_roundtrip(void) {
    nxpsc_access_t in = {.read = 0x0A, .write = 0x0B, .read_write = 0x0C, .change = 0x0D};
    nxpsc_access_t out;

    uint16_t raw = nxpsc_pack_access(&in);
    nxpsc_unpack_access(raw, &out);

    bool ok = (raw == 0xABCD);
    ok = ok && (in.read == out.read) && (in.write == out.write);
    ok = ok && (in.read_write == out.read_write) && (in.change == out.change);

    check("access rights pack/unpack", ok);
}

// AN12196 conditional offsets, mirrors the NTAG 424 DNA example configuration
static void test_sdm_settings(void) {
    nxpsc_access_t access = {.read = 0x0E, .write = 0x00, .read_write = 0x00, .change = 0x00};
    nxpsc_sdm_settings_t sdm = {0};

    sdm.enabled = true;
    sdm.uid_mirror = true;
    sdm.counter_mirror = true;
    sdm.meta_read_key = 0x0E;
    sdm.file_read_key = 0x02;
    sdm.counter_ret_key = 0x0F;
    sdm.uid_offset = 0x000020;
    sdm.counter_offset = 0x000043;
    sdm.mac_input_offset = 0x000043;
    sdm.mac_offset = 0x00004F;

    uint8_t out[64] = {0};
    size_t len = 0;

    bool ok = (nxpsc_sdm_build_settings(NXPSC_COMM_PLAIN, &access, &sdm, out, sizeof(out), &len)
               == NXPSC_OK);
    // options, access(2), sdm options, sdm access(2), three offsets
    ok = ok && (len == 6 + (4 * 3));
    ok = ok && (out[0] == 0x40);                     // SDM and mirroring, plain
    ok = ok && (out[1] == 0x00) && (out[2] == 0xE0);
    ok = ok && (out[3] == 0xC1);                     // UID, counter, ASCII
    ok = ok && (out[4] == 0xFF) && (out[5] == 0xE2);
    ok = ok && (out[6] == 0x20) && (out[7] == 0x00) && (out[8] == 0x00);
    ok = ok && (out[9] == 0x43);
    ok = ok && (out[15] == 0x4F);

    check("NTAG 424 SDM settings layout", ok);

    // SDM disabled leaves only the file option and access rights
    memset(out, 0, sizeof(out));
    sdm.enabled = false;
    ok = (nxpsc_sdm_build_settings(NXPSC_COMM_FULL, &access, &sdm, out, sizeof(out), &len)
          == NXPSC_OK);
    ok = ok && (len == 3) && (out[0] == 0x03);

    check("NTAG 424 SDM disabled layout", ok);
}

static void test_plus_perso(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, PLUS_EV2);
    mock_transport(&mock, &transport);

    uint8_t block[16];
    memset(block, 0xA5, sizeof(block));

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_plus_write_perso(card, 0x4000, block, sizeof(block)) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    ok = ok && (mock.tx[0][0] == 0xA8);
    // the key block address travels little endian
    ok = ok && (mock.tx[0][1] == 0x00) && (mock.tx[0][2] == 0x40);
    ok = ok && (mock.tx_len[0] == 19);

    ok = ok && (nxpsc_plus_commit_perso(card) == NXPSC_OK);
    ok = ok && (mock.tx[1][0] == 0xAA) && (mock.tx_len[1] == 1);

    // SL3 data commands need a session
    ok = ok && (nxpsc_plus_transfer(card, 0x0004) == NXPSC_E_AUTH);

    check("MIFARE Plus personalisation", ok);
    nxpsc_close(card);
}

static void test_guards(void) {
    bool ok = (nxpsc_open(NULL, NULL) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_select_application(NULL, 0) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_pack_access(&(nxpsc_access_t) {
        0x0F, 0x0F, 0x0F, 0x0F
    }) == 0xFFFF);

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    uint8_t uid[16] = {0};
    size_t uid_len = 0;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    ok = ok && (nxpsc_open(&transport, &card) == NXPSC_OK);

    // commands that require a session must refuse without one
    ok = ok && (nxpsc_change_key_settings(card, 0x0F) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_configuration(card, 0x00, NULL, 0) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_select_application(card, 0x01000000) == NXPSC_E_LENGTH);
    ok = ok && (nxpsc_read_data(card, 0x01, 0x01000000, 1, NXPSC_COMM_PLAIN,
                                uid, sizeof(uid), &uid_len) == NXPSC_E_LENGTH);
    ok = ok && (nxpsc_pack_access(NULL) == 0);
    nxpsc_unpack_access(0xFFFF, NULL);

    // without a session GetCardUID falls back to the UID the transport knows
    ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
    ok = ok && (uid_len == 7) && (uid[0] == 0x04);

    // the mock rejects the native GetCardUID, that status must reach the caller
    uint8_t resp[32] = {0};
    size_t resp_len = 0;
    ok = ok && (nxpsc_command(card, 0x51, NULL, 0, NXPSC_COMM_PLAIN, NXPSC_COMM_PLAIN,
                              resp, sizeof(resp), &resp_len) == NXPSC_E_CARD);
    ok = ok && (nxpsc_last_status(card) == 0xAE);

    check("argument and session guards", ok);
    nxpsc_close(card);
}

// the EV2 and later extras must put the documented opcodes on the wire
static void test_advanced_commands(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // ISO chaining swaps the file access opcodes but keeps the payload
    nxpsc_set_iso_chaining(card, true);
    ok = ok && (nxpsc_get_iso_chaining(card) == true);

    uint8_t buf[64] = {0};
    size_t len = 0;
    mock.tx_count = 0;
    nxpsc_read_data(card, 0x01, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len);
    ok = ok && (mock.tx_count == 1) && (mock.tx[0][0] == 0xAD) && (mock.tx_len[0] == 8);

    nxpsc_set_iso_chaining(card, false);
    mock.tx_count = 0;
    nxpsc_read_data(card, 0x01, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len);
    ok = ok && (mock.tx_count == 1) && (mock.tx[0][0] == 0xBD);

    // UpdateRecord carries file, record, offset and length before the data
    const uint8_t rec[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    mock.tx_count = 0;
    nxpsc_update_record(card, 0x02, 0, 4, rec, sizeof(rec), NXPSC_COMM_PLAIN);
    ok = ok && (mock.tx_count == 1) && (mock.tx[0][0] == 0xDB);
    ok = ok && (mock.tx_len[0] == 1 + 10 + sizeof(rec));
    ok = ok && (mock.tx[0][1] == 0x02) && (mock.tx[0][8] == 0x04) && (mock.tx[0][11] == 0xDE);

    // key set management
    mock.tx_count = 0;
    nxpsc_init_key_set(card, 0x01, 3, NXPSC_KEY_AES128);
    ok = ok && (mock.tx[0][0] == 0x56) && (mock.tx[0][1] == 0x01) && (mock.tx[0][2] == 0x83);
    mock.tx_count = 0;
    nxpsc_finalize_key_set(card, 0x01, 0x10);
    ok = ok && (mock.tx[0][0] == 0x57);
    mock.tx_count = 0;
    nxpsc_roll_key_set(card, 0x01);
    ok = ok && (mock.tx[0][0] == 0x55);

    // delegated application management
    mock.tx_count = 0;
    nxpsc_get_delegated_info(card, 0x0102, NULL);
    ok = ok && (mock.tx_count == 0);   // NULL out parameter must be rejected

    // MIFARE Classic mapping and the transaction notification
    const uint8_t mapping[8] = {0};
    mock.tx_count = 0;
    nxpsc_create_mfc_mapping(card, mapping, sizeof(mapping));
    ok = ok && (mock.tx[0][0] == 0xCF);
    mock.tx_count = 0;
    nxpsc_notify_transaction_success(card);
    ok = ok && (mock.tx[0][0] == 0xEE);

    // argument checks on the new calls
    ok = ok && (nxpsc_create_mfc_mapping(card, NULL, 4) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_proximity_check(card, NULL, 1, NULL) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_set_ats(card, mapping, 0) == NXPSC_E_PARAM);

    nxpsc_key_t des = {.type = NXPSC_KEY_DES};
    ok = ok && (nxpsc_proximity_check(card, &des, 1, NULL) == NXPSC_E_UNSUPPORTED);
    ok = ok && (nxpsc_init_key_set(card, 0, 1, NXPSC_KEY_AES256) == NXPSC_E_UNSUPPORTED);

    check("EV2 extras and ISO chaining", ok);
    nxpsc_close(card);
}

// proximity check, end to end against a mock that computes the same CMAC
static void test_proximity_check(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    nxpsc_key_t pc_key = {.type = NXPSC_KEY_AES128};
    memcpy(pc_key.data, mock_pc_key, sizeof(mock_pc_key));

    bool mac_ok = false;
    mock.tx_count = 0;
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 4, &mac_ok) == NXPSC_OK);
    ok = ok && mac_ok;

    // PreparePC, four rounds, VerifyPC
    ok = ok && (mock.tx_count == 6);
    ok = ok && (mock.tx[0][0] == 0xF0);
    ok = ok && (mock.tx[1][0] == 0xF2) && (mock.tx[1][1] == 0x02);
    ok = ok && (mock.tx[5][0] == 0xFD) && (mock.tx_len[5] == 9);

    // a single round has to send the whole challenge at once
    mock.tx_count = 0;
    mac_ok = false;
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 1, &mac_ok) == NXPSC_OK);
    ok = ok && mac_ok && (mock.tx_count == 3) && (mock.tx[1][1] == 0x08);

    // a wrong card MAC must be reported, not silently accepted
    mock.pc_bad_mac = true;
    mac_ok = true;
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 2, &mac_ok) == NXPSC_E_AUTH);
    ok = ok && (mac_ok == false);
    mock.pc_bad_mac = false;

    ok = ok && (nxpsc_proximity_check(card, &pc_key, 0, NULL) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 9, NULL) == NXPSC_E_PARAM);

    check("proximity check", ok);
    nxpsc_close(card);
}

static void test_secure_channel_guards(void) {
    nxpsc_card_t card;
    memset(&card, 0, sizeof(card));
    card.last_cmd = DF_READ_DATA;
    card.mode = MODE_MAC;

    uint8_t out[16] = {0};
    size_t out_len = 0;
    bool ok = true;

    card.channel = NXPSC_CHAN_D40;
    card.key_type = NXPSC_KEY_2K3DES;
    ok = ok && (nxpsc_channel_decode(&card, out, 4, 0x00, out, sizeof(out), &out_len) == NXPSC_E_LENGTH);

    card.channel = NXPSC_CHAN_EV1;
    card.key_type = NXPSC_KEY_AES128;
    ok = ok && (nxpsc_channel_decode(&card, out, 7, 0x00, out, sizeof(out), &out_len) == NXPSC_E_LENGTH);

    card.channel = NXPSC_CHAN_EV2;
    ok = ok && (nxpsc_channel_decode(&card, out, 7, 0x00, out, sizeof(out), &out_len) == NXPSC_E_LENGTH);

    check("secure channel short MAC rejection", ok);
}

static void test_plus_authentication(void) {
    plus_auth_ctx_t ctx = {
        .key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        .rnd_b = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                  0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F},
        .ti = {0xDE, 0xAD, 0xBE, 0xEF},
    };
    nxpsc_transport_t transport = {
        .ctx = &ctx,
        .transceive = plus_auth_transceive,
    };
    nxpsc_card_t *card = NULL;
    nxpsc_key_t key = {.type = NXPSC_KEY_AES128};
    memcpy(key.data, ctx.key, sizeof(ctx.key));

    nxpsc_set_rng(fixed_rng, NULL);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_plus_authenticate(card, 0x4000, &key, true) == NXPSC_OK);
    ok = ok && nxpsc_is_authenticated(card);
    nxpsc_close(card);

    ctx.corrupt_final = true;
    card = NULL;
    ok = ok && (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_plus_authenticate(card, 0x4000, &key, true) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_is_authenticated(card) == false);
    nxpsc_close(card);

    nxpsc_set_rng(NULL, NULL);
    check("MIFARE Plus auth cryptogram check", ok);
}

static void test_plus_missing_mac(void) {
    plus_read_ctx_t ctx = {
        .payload = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        .payload_len = 16,
    };
    nxpsc_transport_t transport = {
        .ctx = &ctx,
        .transceive = plus_read_transceive,
    };
    nxpsc_card_t *card = NULL;

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->authenticated = true;
        card->key_type = NXPSC_KEY_AES128;
        card->channel = NXPSC_CHAN_EV2;
        memcpy(card->session_mac, ctx.payload, 16);
        memcpy(card->session_enc, ctx.payload, 16);
        memcpy(card->ti, "\x01\x02\x03\x04", 4);
    }

    uint8_t out[16] = {0};
    size_t out_len = 0;
    ok = ok && (nxpsc_plus_read(card, 0x0004, 1, false, true, out, sizeof(out), &out_len)
                == NXPSC_E_LENGTH);

    check("MIFARE Plus missing MAC rejection", ok);
    nxpsc_close(card);
}

// delegated application management and the configuration wrappers
static void test_delegation_and_config(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    nxpsc_delegate_info_t info;
    mock.tx_count = 0;
    ok = ok && (nxpsc_get_delegated_info(card, 0x0102, &info) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x69) && (mock.tx[0][1] == 0x02) && (mock.tx[0][2] == 0x01);
    ok = ok && (info.dam_slot_version == 0x05) && (info.quota_limit == 0x0010);
    ok = ok && (info.free_blocks == 0x0020) && (info.aid == 0x332211);

    const uint8_t enck[32] = {0};
    const uint8_t dam_mac[8] = {0};
    const uint8_t df_name[5] = {'D', 'E', 'M', 'O', '1'};

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_delegated_application(card, 0xF51234, 0x0001, 0x00, 0x0010,
                                                   0x0F, 3, NXPSC_KEY_AES128,
                                                   0x1234, df_name, sizeof(df_name),
                                                   enck, sizeof(enck),
                                                   dam_mac, sizeof(dam_mac)) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xC9);
    ok = ok && (mock.tx[0][1] == 0x34) && (mock.tx[0][3] == 0xF5);   // AID, little endian
    ok = ok && (mock.tx[0][9] == 0x0F);                              // key settings
    ok = ok && (mock.tx[0][10] == 0xA3);                             // AES, ISO, 3 keys
    // 57 payload bytes do not fit one frame, the rest follows as 0xAF
    ok = ok && (mock.tx_count == 2);
    ok = ok && (mock.tx_len[0] == 55) && (mock.tx[1][0] == 0xAF) && (mock.tx_len[1] == 4);

    ok = ok && (nxpsc_create_delegated_application(card, 0, 0, 0, 0, 0, 0, NXPSC_KEY_AES128,
                                                   0, NULL, 0, NULL, 0, NULL, 0)
                == NXPSC_E_PARAM);

    // SetConfiguration wrappers all need a session
    const uint8_t ats[5] = {0x06, 0x75, 0x77, 0x81, 0x02};
    nxpsc_key_t key = {.type = NXPSC_KEY_AES128};
    ok = ok && (nxpsc_set_picc_config(card, true, false) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_default_key(card, &key) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_ats(card, ats, sizeof(ats)) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_ats(card, ats, 0) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_set_ats(NULL, ats, sizeof(ats)) == NXPSC_E_PARAM);

    // the transaction MAC file carries a key, so it needs a session and AES
    nxpsc_access_t access = {.read = 0x01, .write = 0x02, .read_write = 0x02, .change = 0x00};
    nxpsc_key_t des = {.type = NXPSC_KEY_DES};
    ok = ok && (nxpsc_create_transaction_mac_file(card, 0x0F, NXPSC_COMM_FULL, &access,
                                                  &des, 0x00) == NXPSC_E_UNSUPPORTED);
    ok = ok && (nxpsc_create_transaction_mac_file(card, 0x0F, NXPSC_COMM_FULL, &access,
                                                  NULL, 0x00) == NXPSC_E_PARAM);
    // without a session the command degrades to plain, the framing must still hold
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_transaction_mac_file(card, 0x0F, NXPSC_COMM_FULL, &access,
                                                  &key, 0x10) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xCE) && (mock.tx_len[0] == 23);
    ok = ok && (mock.tx[0][1] == 0x0F) && (mock.tx[0][2] == 0x03);   // file, full mode
    ok = ok && (mock.tx[0][5] == 0x02);                              // TMKeyOption AES
    ok = ok && (mock.tx[0][22] == 0x10);                             // key version

    check("delegated apps and configuration", ok);
    nxpsc_close(card);
}

// the MIFARE Plus commands added on top of the plain read/write set
static void test_plus_extras(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, PLUS_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // no session, so the block operations must refuse before touching the card
    ok = ok && (nxpsc_plus_value_transfer(card, 0x04, 10, true, true) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_plus_restore(card, 0x04) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_plus_value_transfer(NULL, 0x04, 10, true, true) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_plus_restore(NULL, 0x04) == NXPSC_E_PARAM);

    // the personalisation level commands work without a session
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_personalize_uid(card, 0x00) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x40) && (mock.tx_len[0] == 2);

    const uint8_t cfg[4] = {0x01, 0x02, 0x03, 0x04};
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_set_config_sl1(card, cfg, sizeof(cfg)) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x44) && (mock.tx_len[0] == 1 + sizeof(cfg));
    ok = ok && (nxpsc_plus_set_config_sl1(card, NULL, 4) == NXPSC_E_PARAM);

    uint8_t vc[16] = {0};
    size_t vc_len = 0;
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_vc_support_last_iso_l3(card, vc, sizeof(vc), &vc_len) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x4B);
    ok = ok && (nxpsc_plus_vc_support_last_iso_l3(card, NULL, 0, &vc_len) == NXPSC_E_PARAM);

    // ResetAuth ends the session on both sides
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_reset_auth(card) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x78);
    ok = ok && (nxpsc_is_authenticated(card) == false);

    check("MIFARE Plus extras", ok);
    nxpsc_close(card);
}

int main(void) {
    printf("libnxpsc protocol tests\n");

    test_identify();
    test_version_fields();
    test_native_framing();
    test_iso_wrapping();
    test_iso_wrapping_zero_data();
    test_file_settings();
    test_create_file_framing();
    test_value_and_data();
    test_access_roundtrip();
    test_sdm_settings();
    test_plus_perso();
    test_advanced_commands();
    test_proximity_check();
    test_secure_channel_guards();
    test_plus_authentication();
    test_plus_missing_mac();
    test_delegation_and_config();
    test_plus_extras();
    test_guards();

    if (failures > 0) {
        printf("%d test(s) failed\n", failures);
        return 1;
    }

    printf("all protocol tests passed\n");
    return 0;
}

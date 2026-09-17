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

static bool setup_secure_session(mock_card_t *mock, nxpsc_card_t **card_out, nxpsc_cardtype_t type,
                                 nxpsc_channel_t channel, nxpsc_keytype_t key_type,
                                 const uint8_t *session_enc, const uint8_t *session_mac,
                                 const uint8_t *iv, const uint8_t *ti, uint16_t cmd_ctr) {
    nxpsc_transport_t transport;
    size_t key_len = nxpsc_key_size(key_type);

    mock_init(mock, type);
    mock_transport(mock, &transport);

    if (nxpsc_open(&transport, card_out) != NXPSC_OK) {
        return false;
    }

    mock->secure_active = true;
    mock->secure_channel = channel;
    mock->secure_key_type = key_type;
    memcpy(mock->secure_session_enc, session_enc, key_len);
    memcpy(mock->secure_session_mac, session_mac, key_len);
    memcpy(mock->secure_iv, iv, sizeof(mock->secure_iv));
    memcpy(mock->secure_ti, ti, sizeof(mock->secure_ti));
    mock->secure_cmd_ctr = cmd_ctr;

    (*card_out)->authenticated = true;
    (*card_out)->channel = channel;
    (*card_out)->key_type = key_type;
    (*card_out)->type = type;
    memcpy((*card_out)->session_enc, session_enc, key_len);
    memcpy((*card_out)->session_mac, session_mac, key_len);
    memcpy((*card_out)->iv, iv, sizeof((*card_out)->iv));
    memcpy((*card_out)->ti, ti, sizeof((*card_out)->ti));
    (*card_out)->cmd_ctr = cmd_ctr;
    return true;
}

static bool run_exact_buffer_read_case(nxpsc_cardtype_t type, nxpsc_channel_t channel,
                                       nxpsc_keytype_t key_type, nxpsc_commmode_t comm) {
    static const uint8_t session_enc[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    static const uint8_t session_mac[16] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, type, channel, key_type,
                                   session_enc, session_mac, iv, ti, 0);
    if (ok == false) {
        return false;
    }

    mock.read_comm = comm;
    mock.read_len = 64;
    mock.validate_secure_requests = (channel == NXPSC_CHAN_EV2);

    uint8_t buf[64] = {0};
    size_t len = 0;

    ok = (nxpsc_read_data(card, 0x01, 0, 64, comm, buf, sizeof(buf), &len) == NXPSC_OK);
    ok = ok && (len == sizeof(buf));
    for (size_t i = 0; ok && i < sizeof(buf); i++) {
        ok = ok && (buf[i] == (uint8_t)i);
    }

    nxpsc_close(card);
    return ok;
}

static void setup_mock_auth(mock_card_t *mock, mock_auth_scheme_t scheme,
                            const nxpsc_key_t *key, const uint8_t *rnd_b) {
    size_t key_len = nxpsc_key_size(key->type);
    size_t rnd_len = nxpsc_block_size(key->type);

    mock->auth_scheme = scheme;
    mock->auth_key_type = key->type;
    memcpy(mock->auth_key, key->data, key_len);
    memset(mock->auth_rnd_b, 0, sizeof(mock->auth_rnd_b));
    memcpy(mock->auth_rnd_b, rnd_b, rnd_len);
}

static bool auth_frame_has_payload(const mock_card_t *mock, size_t index) {
    if (index >= mock->tx_count) {
        return false;
    }
    return mock->tx_len[index] > 5 &&
           mock->tx[index][0] == 0x90 &&
           mock->tx[index][1] == 0xAF &&
           mock->tx[index][4] > 0;
}

static bool run_desfire_auth_case(nxpsc_cardtype_t type, nxpsc_channel_t channel,
                                  mock_auth_scheme_t scheme, const nxpsc_key_t *key,
                                  const uint8_t *rnd_b, uint8_t first_cmd,
                                  bool include_nonfirst) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, type);
    setup_mock_auth(&mock, scheme, key, rnd_b);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);
    }

    ok = ok && (nxpsc_authenticate(card, 0x00, key, channel) == NXPSC_OK);
    ok = ok && nxpsc_is_authenticated(card);
    ok = ok && (mock.tx_count == 2);
    ok = ok && (mock.tx[0][0] == 0x90) && (mock.tx[0][1] == first_cmd);
    ok = ok && auth_frame_has_payload(&mock, 1);

    if (ok && include_nonfirst) {
        mock.tx_count = 0;
        setup_mock_auth(&mock, scheme, key, rnd_b);
        ok = ok && (nxpsc_authenticate_nonfirst(card, 0x01, key) == NXPSC_OK);
        ok = ok && nxpsc_is_authenticated(card);
        ok = ok && (mock.tx_count == 2);
        ok = ok && (mock.tx[0][0] == 0x90) && (mock.tx[0][1] == 0x77);
        ok = ok && auth_frame_has_payload(&mock, 1);
    }

    nxpsc_close(card);
    return ok;
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
    ok = ok && (version.sw_type == 0x01);
    ok = ok && (version.sw_major == 0x03);
    ok = ok && (version.sw_minor == 0x00);
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

static void test_desfire_authentication(void) {
    const nxpsc_key_t key_d40 = {
        .type = NXPSC_KEY_2K3DES,
        .data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    };
    const nxpsc_key_t key_ev1 = {
        .type = NXPSC_KEY_2K3DES,
        .data = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    };
    const nxpsc_key_t key_aes = {
        .type = NXPSC_KEY_AES128,
        .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    };
    const uint8_t rnd_b8[8] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87};
    const uint8_t rnd_b16[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};

    nxpsc_set_rng(fixed_rng, NULL);

    bool ok = run_desfire_auth_case(DESFIRE_MF3ICD40, NXPSC_CHAN_D40, MOCK_AUTH_LEGACY,
                                    &key_d40, rnd_b8, 0x0A, false);
    ok = ok && run_desfire_auth_case(DESFIRE_EV1, NXPSC_CHAN_EV1, MOCK_AUTH_LEGACY,
                                     &key_ev1, rnd_b8, 0x1A, false);
    ok = ok && run_desfire_auth_case(DESFIRE_EV2, NXPSC_CHAN_EV2, MOCK_AUTH_EV2,
                                     &key_aes, rnd_b16, 0x71, true);
    ok = ok && run_desfire_auth_case(DESFIRE_LIGHT, NXPSC_CHAN_LRP, MOCK_AUTH_LRP,
                                     &key_aes, rnd_b16, 0x71, true);

    nxpsc_set_rng(NULL, NULL);
    check("DESFire auth handshake AF handling", ok);
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
    nxpsc_init_key_set(card, 0x01, NXPSC_KEY_AES128);
    // two bytes, key set then the new set's key type carried unshifted.
    // EV3 answers 0x7E to any other length
    ok = ok && (mock.tx_len[0] == 3);
    ok = ok && (mock.tx[0][0] == 0x56) && (mock.tx[0][1] == 0x01) && (mock.tx[0][2] == 0x02);
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
    ok = ok && (nxpsc_init_key_set(NULL, 0, NXPSC_KEY_AES128) == NXPSC_E_PARAM);

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

static void test_secure_channel_exact_buffers(void) {
    check("D40 MAC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_MF3ICD40, NXPSC_CHAN_D40,
                                     NXPSC_KEY_2K3DES, NXPSC_COMM_MAC));
    check("D40 ENC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_MF3ICD40, NXPSC_CHAN_D40,
                                     NXPSC_KEY_2K3DES, NXPSC_COMM_FULL));
    check("EV1 MAC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV1, NXPSC_CHAN_EV1,
                                     NXPSC_KEY_AES128, NXPSC_COMM_MAC));
    check("EV1 ENC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV1, NXPSC_CHAN_EV1,
                                     NXPSC_KEY_AES128, NXPSC_COMM_FULL));
    check("EV2 MAC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV2, NXPSC_CHAN_EV2,
                                     NXPSC_KEY_AES128, NXPSC_COMM_MAC));
    check("EV2 ENC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV2, NXPSC_CHAN_EV2,
                                     NXPSC_KEY_AES128, NXPSC_COMM_FULL));
}

static bool run_legacy_get_card_uid_case(bool ev1_style_crc) {
    static const uint8_t session[16] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0};

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV3, NXPSC_CHAN_D40,
                                   NXPSC_KEY_2K3DES, session, session, iv, ti, 0);

    uint8_t uid[7] = {0};
    size_t uid_len = 0;

    if (ok) {
        mock.d40_ev1_style_uid = ev1_style_crc;
        ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
        ok = ok && (uid_len == sizeof(uid));
        ok = ok && (memcmp(uid, mock.uid, sizeof(uid)) == 0);
    }

    nxpsc_close(card);
    return ok;
}

// a legacy session always enciphers the same way. EV3 answers GetCardUID with
// the legacy CRC16, confirmed against the card, but the decoder accepts the
// EV1 style CRC32 too because later silicon is not consistent about it
// CreateApplication has four optional blocks and the order matters. the key set
// block sits between KeySett2 and the ISO fields, not after them
static void test_create_application_layout(void) {
    static const uint8_t df_name[3] = {0xAA, 0xBB, 0xCC};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok == false) {
        check("CreateApplication payload layout", false);
        return;
    }

    // plain application, no ISO fields and no key sets
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application(card, 0x010203, 0x0F, 3, NXPSC_KEY_AES128) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 6);
    ok = ok && (mock.tx[0][0] == DF_CREATE_APPLICATION);
    ok = ok && (mock.tx[0][1] == 0x03) && (mock.tx[0][2] == 0x02) && (mock.tx[0][3] == 0x01);
    ok = ok && (mock.tx[0][4] == 0x0F);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80));

    // ISO fid and DF name, still no key sets
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application_iso(card, 0x010203, 0x0F, 3, NXPSC_KEY_AES128,
                                             0xE110, df_name, sizeof(df_name)) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 11);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80 | 0x20));
    ok = ok && (mock.tx[0][6] == 0x10) && (mock.tx[0][7] == 0xE1);
    ok = ok && (memcmp(&mock.tx[0][8], df_name, sizeof(df_name)) == 0);

    // key sets, announced by bit 4 of KeySett2, block placed before the ISO fields
    nxpsc_app_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.iso_fid_enabled = true;
    cfg.iso_fid = 0xE110;
    cfg.df_name = df_name;
    cfg.df_name_len = sizeof(df_name);
    cfg.num_key_sets = 2;
    cfg.key_set_version = 0x11;
    cfg.max_key_size = 16;
    cfg.key_set_settings = 0x02;    // three bits wide, the roll key

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 16);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80 | 0x20 | 0x10));
    ok = ok && (mock.tx[0][6] == 0x01);     // KeySett3, key sets enabled
    ok = ok && (mock.tx[0][7] == 0x11);     // AKSVersion
    ok = ok && (mock.tx[0][8] == 0x02);     // NoKeySets
    ok = ok && (mock.tx[0][9] == 16);       // MaxKeySize
    ok = ok && (mock.tx[0][10] == 0x02);    // AppKeySetSett
    ok = ok && (mock.tx[0][11] == 0x10) && (mock.tx[0][12] == 0xE1);
    ok = ok && (memcmp(&mock.tx[0][13], df_name, sizeof(df_name)) == 0);

    // specific VC keys ride in KeySett3 without bringing the key set block,
    // so the ISO fields follow it straight away
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.iso_fid_enabled = true;
    cfg.iso_fid = 0xE110;
    cfg.specific_vc_keys = true;

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 9);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80 | 0x20 | 0x10));
    ok = ok && (mock.tx[0][6] == 0x02);     // KeySett3, VC keys only
    ok = ok && (mock.tx[0][7] == 0x10) && (mock.tx[0][8] == 0xE1);

    // one key set is not a set, the caller meant either none or at least two
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.num_key_sets = 1;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_E_PARAM);

    // AppKeySetSett is three bits wide
    cfg.num_key_sets = 2;
    cfg.max_key_size = 16;
    cfg.key_set_settings = 0x0F;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_E_PARAM);

    check("CreateApplication payload layout", ok);
    nxpsc_close(card);
}

static void test_legacy_get_card_uid(void) {
    check("legacy GetCardUID, CRC16 payload", run_legacy_get_card_uid_case(false));
    check("legacy GetCardUID, CRC32 payload", run_legacy_get_card_uid_case(true));
}

// a 2TDEA key with two equal halves is a DES key. the PICC cannot tell the two
// apart from the key type alone and derives the shorter session key, which the
// handshake never exposes because 3DES with K1 == K2 is single DES
static void test_legacy_des_degraded_session_key(void) {
    // fixed_rng() and the mock both build RndA as 0x10 + index
    static const uint8_t rnd_a[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    static const uint8_t rnd_b[8] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};

    nxpsc_key_t key;
    memset(&key, 0, sizeof(key));
    key.type = NXPSC_KEY_2K3DES;

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->type = DESFIRE_EV3;
        mock.auth_scheme = MOCK_AUTH_LEGACY;
        mock.auth_key_type = NXPSC_KEY_2K3DES;
        memset(mock.auth_key, 0, sizeof(mock.auth_key));
        memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));
        nxpsc_set_rng(fixed_rng, NULL);

        ok = ok && (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_D40) == NXPSC_OK);
        nxpsc_set_rng(NULL, NULL);
    }

    if (ok) {
        // DES session key, RndA[0..3] || RndB[0..3], held duplicated
        uint8_t want[16] = {0};
        memcpy(want, rnd_a, 4);
        memcpy(want + 4, rnd_b, 4);
        memcpy(want + 8, want, 8);
        ok = ok && (memcmp(card->session_enc, want, sizeof(want)) == 0);
        ok = ok && (memcmp(mock.secure_session_enc, want, sizeof(want)) == 0);

        // and the first command on that session decodes, which is the only
        // place a wrong derivation would ever show up
        uint8_t uid[7] = {0};
        size_t uid_len = 0;
        ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
        ok = ok && (uid_len == sizeof(uid));
        ok = ok && (memcmp(uid, mock.uid, sizeof(uid)) == 0);
    }

    check("legacy DES degraded session key", ok);
    nxpsc_close(card);
}

// an error answer inside a session is not a counter problem, the PICC has
// already thrown the session away by the time it sends one
static void test_session_abort_on_card_error(void) {
    const nxpsc_key_t key = {
        .type = NXPSC_KEY_AES128,
        .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    };
    static const uint8_t rnd_b[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                      0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    mock.auth_key_type = NXPSC_KEY_AES128;
    memcpy(mock.auth_key, key.data, sizeof(mock.auth_key));
    memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));

    nxpsc_set_rng(fixed_rng, NULL);
    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->type = DESFIRE_EV2;
        ok = (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
    }

    if (ok) {
        mock.validate_secure_requests = true;
        mock.reject_cmd = DF_CHANGE_KEY_SETTINGS;
        mock.reject_status = 0x9D;

        uint8_t settings = 0x0F;
        uint8_t resp[8] = {0};
        size_t resp_len = 0;
        ok = ok && (nxpsc_command(card, DF_CHANGE_KEY_SETTINGS, &settings, 1,
                                  NXPSC_COMM_PLAIN, NXPSC_COMM_PLAIN,
                                  resp, sizeof(resp), &resp_len) == NXPSC_E_CARD);
        ok = ok && (nxpsc_last_status(card) == 0x9D);

        // both sides dropped the session, and ours says so
        ok = ok && (nxpsc_is_authenticated(card) == false);
        ok = ok && nxpsc_session_lost(card);
        ok = ok && (mock.secure_active == false);

        // the next command that needs the session fails locally, without
        // putting a MACed frame on the wire for the card to read as garbage
        size_t before = mock.tx_count;
        uint32_t aids[2] = {0};
        size_t count = 0;
        ok = ok && (nxpsc_get_application_ids(card, aids, 2, &count) == NXPSC_E_AUTH);
        ok = ok && (mock.tx_count == before);

        // authenticating again restores service
        ok = ok && (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
        ok = ok && (nxpsc_session_lost(card) == false);
        ok = ok && (nxpsc_get_application_ids(card, aids, 2, &count) == NXPSC_OK);
        ok = ok && (count == 2);
        ok = ok && (aids[0] == 0x030201) && (aids[1] == 0x332211);
        ok = ok && (card->cmd_ctr == mock.secure_cmd_ctr);
    }

    nxpsc_set_rng(NULL, NULL);
    check("session dropped after card error", ok);
    nxpsc_close(card);
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
    test_desfire_authentication();
    test_file_settings();
    test_create_file_framing();
    test_value_and_data();
    test_access_roundtrip();
    test_sdm_settings();
    test_plus_perso();
    test_advanced_commands();
    test_proximity_check();
    test_secure_channel_guards();
    test_secure_channel_exact_buffers();
    test_create_application_layout();
    test_legacy_get_card_uid();
    test_legacy_des_degraded_session_key();
    test_session_abort_on_card_error();
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

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
// libnxpsc - crypto known answer tests, ported from the proxmark3 client
// suite client/src/mifare/desfiretest.c. sources of the vectors:
//   AN10922 (diversification), AN12343 (EV2 / LRP secure messaging),
//   AN12304 (LRP), NIST SP 800-38B examples (TDES CMAC)
//-----------------------------------------------------------------------------

#include "nxpsc_internal.h"

#include <stdio.h>
#include <string.h>

static bool report(const char *name, bool ok, bool verbose) {
    if (verbose) {
        printf("%-24s %s\n", name, ok ? "ok" : "FAIL");
    } else if (ok == false) {
        printf("%-24s FAIL\n", name);
    }
    return ok;
}

static const uint8_t cmac_data[32] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51
};

static bool test_crc_search(void) {
    uint8_t d16[16] = {0x04, 0x44, 0x0F, 0x32, 0x76, 0x31, 0x80, 0x27, 0x98};
    bool res = (nxpsc_search_crc_pos(d16, 16, 0x00, 2) == 7);
    res = res && (nxpsc_search_crc_pos(d16, 9, 0x00, 2) == 7);
    res = res && (nxpsc_search_crc_pos(d16, 7, 0x00, 2) == 0);
    res = res && (nxpsc_search_crc_pos(d16, 1, 0x00, 2) == 0);

    uint8_t d32[16] = {0x04, 0x44, 0x0F, 0x32, 0x76, 0x31, 0x80, 0x99, 0xCE, 0x1A, 0xD4};
    res = res && (nxpsc_search_crc_pos(d32, 16, 0x00, 4) == 7);
    res = res && (nxpsc_search_crc_pos(d32, 11, 0x00, 4) == 7);
    res = res && (nxpsc_search_crc_pos(d32, 5, 0x00, 4) == 0);
    res = res && (nxpsc_search_crc_pos(d32, 2, 0x00, 4) == 0);
    return res;
}

static bool test_cmac_subkeys(void) {
    const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
                            };
    uint8_t sk1[NXPSC_MAX_BLOCK] = {0};
    uint8_t sk2[NXPSC_MAX_BLOCK] = {0};

    const uint8_t sk1_aes[16] = {0xFB, 0xC9, 0xF7, 0x5C, 0x94, 0x13, 0xC0, 0x41,
                                 0xDF, 0xEE, 0x45, 0x2D, 0x3F, 0x07, 0x06, 0xD1
                                };
    const uint8_t sk2_aes[16] = {0xF7, 0x93, 0xEE, 0xB9, 0x28, 0x27, 0x80, 0x83,
                                 0xBF, 0xDC, 0x8A, 0x5A, 0x7E, 0x0E, 0x0D, 0x25
                                };

    nxpsc_cmac_subkeys(NXPSC_KEY_AES128, key, sk1, sk2);
    bool res = (memcmp(sk1, sk1_aes, 16) == 0) && (memcmp(sk2, sk2_aes, 16) == 0);

    const uint8_t sk1_2k[8] = {0xF6, 0x12, 0xEB, 0x32, 0xE4, 0x60, 0x35, 0xF3};
    const uint8_t sk2_2k[8] = {0xEC, 0x25, 0xD6, 0x65, 0xC8, 0xC0, 0x6B, 0xFD};

    nxpsc_cmac_subkeys(NXPSC_KEY_2K3DES, key, sk1, sk2);
    res = res && (memcmp(sk1, sk1_2k, 8) == 0) && (memcmp(sk2, sk2_2k, 8) == 0);

    const uint8_t key3[24] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
                             };
    const uint8_t sk1_3k[8] = {0xA3, 0xED, 0x58, 0xF8, 0xE6, 0x94, 0x1B, 0xCA};
    const uint8_t sk2_3k[8] = {0x47, 0xDA, 0xB1, 0xF1, 0xCD, 0x28, 0x37, 0x8F};

    nxpsc_cmac_subkeys(NXPSC_KEY_3K3DES, key3, sk1, sk2);
    res = res && (memcmp(sk1, sk1_3k, 8) == 0) && (memcmp(sk2, sk2_3k, 8) == 0);
    return res;
}

static bool cmac_case(nxpsc_keytype_t type, const uint8_t *key, size_t len,
                      const uint8_t *expected) {
    uint8_t iv[NXPSC_MAX_BLOCK] = {0};
    uint8_t mac[NXPSC_MAX_BLOCK] = {0};

    if (nxpsc_cmac(type, key, iv, cmac_data, len, 0, mac) != NXPSC_OK) {
        return false;
    }
    return memcmp(mac, expected, 8) == 0;
}

static bool test_cmac_tdes(void) {
    const uint8_t key3[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                              0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
                              0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
                             };
    const uint8_t m0[8] = {0x7D, 0xB0, 0xD3, 0x7D, 0xF9, 0x36, 0xC5, 0x50};
    const uint8_t m16[8] = {0x30, 0x23, 0x9C, 0xF1, 0xF5, 0x2E, 0x66, 0x09};
    const uint8_t m20[8] = {0x6C, 0x9F, 0x3E, 0xE4, 0x92, 0x3F, 0x6B, 0xE2};
    const uint8_t m32[8] = {0x99, 0x42, 0x9B, 0xD0, 0xBF, 0x79, 0x04, 0xE5};

    bool res = cmac_case(NXPSC_KEY_3K3DES, key3, 0, m0);
    res = res && cmac_case(NXPSC_KEY_3K3DES, key3, 16, m16);
    res = res && cmac_case(NXPSC_KEY_3K3DES, key3, 20, m20);
    res = res && cmac_case(NXPSC_KEY_3K3DES, key3, 32, m32);

    const uint8_t key2[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                              0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
                             };
    const uint8_t n0[8] = {0x79, 0xCE, 0x52, 0xA7, 0xF7, 0x86, 0xA9, 0x60};
    const uint8_t n16[8] = {0xCC, 0x18, 0xA0, 0xB7, 0x9A, 0xF2, 0x41, 0x3B};
    const uint8_t n20[8] = {0xC0, 0x6D, 0x37, 0x7E, 0xCD, 0x10, 0x19, 0x69};
    const uint8_t n32[8] = {0x9C, 0xD3, 0x35, 0x80, 0xF9, 0xB6, 0x4D, 0xFB};

    res = res && cmac_case(NXPSC_KEY_2K3DES, key2, 0, n0);
    res = res && cmac_case(NXPSC_KEY_2K3DES, key2, 16, n16);
    res = res && cmac_case(NXPSC_KEY_2K3DES, key2, 20, n20);
    res = res && cmac_case(NXPSC_KEY_2K3DES, key2, 32, n32);

    const uint8_t key1[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    const uint8_t o0[8] = {0x86, 0xF7, 0x9C, 0x13, 0xFD, 0x30, 0x6E, 0x67};
    const uint8_t o16[8] = {0xBE, 0xA4, 0x21, 0x22, 0x92, 0x46, 0x2A, 0x85};
    const uint8_t o20[8] = {0x3E, 0x2F, 0x83, 0x10, 0xC5, 0x69, 0x27, 0x5E};
    const uint8_t o32[8] = {0x9D, 0x1F, 0xC4, 0xD4, 0xC0, 0x25, 0x91, 0x32};

    res = res && cmac_case(NXPSC_KEY_DES, key1, 0, o0);
    res = res && cmac_case(NXPSC_KEY_DES, key1, 16, o16);
    res = res && cmac_case(NXPSC_KEY_DES, key1, 20, o20);
    res = res && cmac_case(NXPSC_KEY_DES, key1, 32, o32);
    return res;
}

static bool test_an10922(void) {
    nxpsc_key_t master = {0};
    nxpsc_key_t out = {0};

    const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
                            };
    const uint8_t input[17] = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42,
                               0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41, 0x62, 0x75
                              };

    master.type = NXPSC_KEY_AES128;
    memcpy(master.data, key, 16);

    const uint8_t aes[16] = {0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3,
                             0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75
                            };
    bool res = (nxpsc_kdf_an10922(&master, input, 17, &out) == NXPSC_OK);
    res = res && (memcmp(out.data, aes, 16) == 0);

    master.type = NXPSC_KEY_2K3DES;
    const uint8_t tdea2[16] = {0x16, 0xF8, 0x59, 0x7C, 0x9E, 0x89, 0x10, 0xC8,
                               0x6B, 0x96, 0x48, 0xD0, 0x06, 0x10, 0x7D, 0xD7
                              };
    res = res && (nxpsc_kdf_an10922(&master, input, 15, &out) == NXPSC_OK);
    res = res && (memcmp(out.data, tdea2, 16) == 0);

    const uint8_t key3[24] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
                             };
    master.type = NXPSC_KEY_3K3DES;
    memcpy(master.data, key3, 24);

    const uint8_t tdea3[24] = {0x2F, 0x0D, 0xD0, 0x36, 0x75, 0xD3, 0xFB, 0x9A,
                               0x57, 0x05, 0xAB, 0x0B, 0xDA, 0x91, 0xCA, 0x0B,
                               0x55, 0xB8, 0xE0, 0x7F, 0xCD, 0xBF, 0x10, 0xEC
                              };
    res = res && (nxpsc_kdf_an10922(&master, input, 13, &out) == NXPSC_OK);
    res = res && (memcmp(out.data, tdea3, 24) == 0);
    return res;
}

static bool test_ev2_session_keys(void) {
    const uint8_t key[16] = {0};
    const uint8_t rnda[16] = {0xB0, 0x4D, 0x07, 0x87, 0xC9, 0x3E, 0xE0, 0xCC,
                              0x8C, 0xAC, 0xC8, 0xE8, 0x6F, 0x16, 0xC6, 0xFE
                             };
    const uint8_t rndb[16] = {0xFA, 0x65, 0x9A, 0xD0, 0xDC, 0xA7, 0x38, 0xDD,
                              0x65, 0xDC, 0x7D, 0xC3, 0x86, 0x12, 0xAD, 0x81
                             };
    const uint8_t enc[16] = {0x63, 0xDC, 0x07, 0x28, 0x62, 0x89, 0xA7, 0xA6,
                             0xC0, 0x33, 0x4C, 0xA3, 0x1C, 0x31, 0x4A, 0x04
                            };
    const uint8_t mac[16] = {0x77, 0x4F, 0x26, 0x74, 0x3E, 0xCE, 0x6A, 0xF5,
                             0x03, 0x3B, 0x6A, 0xE8, 0x52, 0x29, 0x46, 0xF6
                            };

    uint8_t out[16] = {0};
    bool res = (nxpsc_session_key_ev2(key, rnda, rndb, true, out) == NXPSC_OK);
    res = res && (memcmp(out, enc, 16) == 0);

    res = res && (nxpsc_session_key_ev2(key, rnda, rndb, false, out) == NXPSC_OK);
    res = res && (memcmp(out, mac, 16) == 0);
    return res;
}

static bool test_ev2_iv(void) {
    nxpsc_card_t card;
    memset(&card, 0, sizeof(card));

    const uint8_t key[16] = {0x66, 0xA8, 0xCB, 0x93, 0x26, 0x9D, 0xC9, 0xBC,
                             0x28, 0x85, 0xB7, 0xA9, 0x1B, 0x9C, 0x69, 0x7B
                            };
    const uint8_t ti[4] = {0xED, 0x56, 0xF6, 0xE6};
    const uint8_t expected[16] = {0xDA, 0x0F, 0x64, 0x4A, 0x49, 0x86, 0x27, 0x59,
                                  0x57, 0xCF, 0x1E, 0xC3, 0xAF, 0x4C, 0xCE, 0x53
                                 };

    card.key_type = NXPSC_KEY_AES128;
    memcpy(card.session_enc, key, 16);
    memcpy(card.ti, ti, 4);
    card.cmd_ctr = 0;

    uint8_t iv[16] = {0};
    nxpsc_ev2_fill_iv(&card, true, iv);
    bool res = (memcmp(iv, expected, 16) == 0);

    const uint8_t key2[16] = {0x44, 0x5A, 0x86, 0x26, 0xB3, 0x33, 0x84, 0x59,
                              0x32, 0x12, 0x32, 0xFA, 0xDF, 0x6A, 0xDE, 0x2B
                             };
    const uint8_t ti2[4] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t expected2[16] = {0x17, 0x74, 0x94, 0xFC, 0xC4, 0xF1, 0xDA, 0xB2,
                                   0xAF, 0xBE, 0x8F, 0xAE, 0x20, 0x57, 0xA9, 0xD2
                                  };

    memcpy(card.session_enc, key2, 16);
    memcpy(card.ti, ti2, 4);
    card.cmd_ctr = 5;

    memset(iv, 0, sizeof(iv));
    nxpsc_ev2_fill_iv(&card, true, iv);
    res = res && (memcmp(iv, expected2, 16) == 0);
    return res;
}

static bool test_ev2_mac(void) {
    nxpsc_card_t card;
    memset(&card, 0, sizeof(card));

    const uint8_t key[16] = {0x93, 0x66, 0xFA, 0x19, 0x5E, 0xB5, 0x66, 0xF5,
                             0xBD, 0x2B, 0xAD, 0x40, 0x20, 0xB8, 0x30, 0x02
                            };
    const uint8_t ti[4] = {0xE2, 0xD3, 0xAF, 0x69};
    const uint8_t data[32] = {0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00,
                              0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                              0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                              0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
                             };
    const uint8_t expected[8] = {0x68, 0xF2, 0xC2, 0x8C, 0x57, 0x5A, 0x16, 0x28};

    card.channel = NXPSC_CHAN_EV2;
    card.key_type = NXPSC_KEY_AES128;
    memcpy(card.session_mac, key, 16);
    memcpy(card.ti, ti, 4);

    uint8_t mac[8] = {0};
    bool res = (nxpsc_ev2_cmac(&card, 0x8D, data, sizeof(data), mac) == NXPSC_OK);
    res = res && (memcmp(mac, expected, 8) == 0);

    // response MAC of the same exchange, command counter has moved on
    const uint8_t expected2[8] = {0x08, 0x20, 0xF6, 0x88, 0x98, 0xC2, 0xA7, 0xF1};
    card.cmd_ctr++;
    memset(mac, 0, sizeof(mac));
    res = res && (nxpsc_ev2_cmac(&card, 0x00, NULL, 0, mac) == NXPSC_OK);
    res = res && (memcmp(mac, expected2, 8) == 0);
    return res;
}

static bool test_trans_session_keys(void) {
    const uint8_t key[16] = {0x66, 0xA8, 0xCB, 0x93, 0x26, 0x9D, 0xC9, 0xBC,
                             0x28, 0x85, 0xB7, 0xA9, 0x1B, 0x9C, 0x69, 0x7B
                            };
    const uint8_t uid[7] = {0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    const uint8_t key_mac[16] = {0x7C, 0x1A, 0xD2, 0xD9, 0xC5, 0xC0, 0x81, 0x54,
                                 0xA0, 0xA4, 0x91, 0x4B, 0x40, 0x1A, 0x65, 0x98
                                };
    const uint8_t key_enc[16] = {0x11, 0x9B, 0x90, 0x2A, 0x07, 0xB1, 0x8A, 0x86,
                                 0x5B, 0x8E, 0x1B, 0x00, 0x60, 0x59, 0x47, 0x84
                                };

    uint8_t out[16] = {0};
    bool res = (nxpsc_trans_session_key_ev2(key, 8, uid, true, out) == NXPSC_OK);
    res = res && (memcmp(out, key_mac, 16) == 0);

    res = res && (nxpsc_trans_session_key_ev2(key, 8, uid, false, out) == NXPSC_OK);
    res = res && (memcmp(out, key_enc, 16) == 0);
    return res;
}

static bool test_lrp_plaintexts(void) {
    const uint8_t key[16] = {0x56, 0x78, 0x26, 0xB8, 0xDA, 0x8E, 0x76, 0x84,
                             0x32, 0xA9, 0x54, 0x8D, 0xBE, 0x4A, 0xA3, 0xA0
                            };
    nxpsc_lrp_ctx_t ctx;
    nxpsc_lrp_init(&ctx, key, 0, false);

    const uint8_t pt0[16] = {0xAC, 0x20, 0xD3, 0x9F, 0x53, 0x41, 0xFE, 0x98,
                             0xDF, 0xCA, 0x21, 0xDA, 0x86, 0xBA, 0x79, 0x14
                            };
    const uint8_t pt15[16] = {0x71, 0xB4, 0x44, 0xAF, 0x25, 0x7A, 0x93, 0x21,
                              0x53, 0x11, 0xD7, 0x58, 0xDD, 0x33, 0x32, 0x47
                             };
    bool res = (memcmp(ctx.plaintexts[0], pt0, 16) == 0);
    res = res && (memcmp(ctx.plaintexts[15], pt15, 16) == 0);

    const uint8_t uk0[16] = {0x16, 0x3D, 0x14, 0xED, 0x24, 0xED, 0x93, 0x53,
                             0x73, 0x56, 0x8E, 0xC5, 0x21, 0xE9, 0x6C, 0xF4
                            };
    const uint8_t uk2[16] = {0xFE, 0x30, 0xAB, 0x50, 0x46, 0x7E, 0x61, 0x78,
                             0x3B, 0xFE, 0x6B, 0x5E, 0x05, 0x60, 0x16, 0x0E
                            };
    res = res && (memcmp(ctx.updated_keys[0], uk0, 16) == 0);
    res = res && (memcmp(ctx.updated_keys[2], uk2, 16) == 0);
    return res;
}

static bool test_lrp_eval(void) {
    nxpsc_lrp_ctx_t ctx;
    uint8_t y[16] = {0};

    const uint8_t key[16] = {0x56, 0x78, 0x26, 0xB8, 0xDA, 0x8E, 0x76, 0x84,
                             0x32, 0xA9, 0x54, 0x8D, 0xBE, 0x4A, 0xA3, 0xA0
                            };
    const uint8_t iv[2] = {0x13, 0x59};
    const uint8_t y1[16] = {0x1B, 0xA2, 0xC0, 0xC5, 0x78, 0x99, 0x6B, 0xC4,
                            0x97, 0xDD, 0x18, 0x1C, 0x68, 0x85, 0xA9, 0xDD
                           };

    nxpsc_lrp_init(&ctx, key, 2, false);
    nxpsc_lrp_eval(&ctx, iv, sizeof(iv) * 2, true, y);
    bool res = (memcmp(y, y1, 16) == 0);

    const uint8_t key2[16] = {0xB6, 0x55, 0x57, 0xCE, 0x0E, 0x9B, 0x4C, 0x58,
                              0x86, 0xF2, 0x32, 0x20, 0x01, 0x13, 0x56, 0x2B
                             };
    const uint8_t iv2[12] = {0xBB, 0x4F, 0xCF, 0x27, 0xC9, 0x40,
                             0x76, 0xF7, 0x56, 0xAB, 0x03, 0x0D
                            };
    const uint8_t y2[16] = {0x6F, 0xDF, 0xA8, 0xD2, 0xA6, 0xAA, 0x84, 0x76,
                            0xBF, 0x94, 0xE7, 0x1F, 0x25, 0x63, 0x7F, 0x96
                           };

    nxpsc_lrp_init(&ctx, key2, 1, false);
    nxpsc_lrp_eval(&ctx, iv2, sizeof(iv2) * 2, false, y);
    res = res && (memcmp(y, y2, 16) == 0);

    // odd nibble count, exercises the half byte handling
    const uint8_t key3[16] = {0xC4, 0x8A, 0x8E, 0x8B, 0x16, 0x57, 0x16, 0x45,
                              0xA1, 0x55, 0x78, 0x25, 0xAA, 0x66, 0xAC, 0x91
                             };
    const uint8_t iv3[16] = {0x1F, 0x0B, 0x7C, 0x0D, 0xB1, 0x28, 0x89, 0xCA,
                             0x43, 0x6C, 0xAB, 0xB7, 0x8B, 0xE4, 0x2F, 0x90
                            };
    const uint8_t y3[16] = {0x51, 0x29, 0x6B, 0x5E, 0x6D, 0x3B, 0x8D, 0xB8,
                            0xA1, 0xA7, 0x39, 0x97, 0x60, 0xA1, 0x91, 0x89
                           };

    nxpsc_lrp_init(&ctx, key3, 3, false);
    nxpsc_lrp_eval(&ctx, iv3, sizeof(iv3) * 2 - 1, true, y);
    res = res && (memcmp(y, y3, 16) == 0);
    return res;
}

static bool test_lrp_counter(void) {
    uint8_t c1[2] = {0x00, 0x01};
    const uint8_t r1[2] = {0x00, 0x02};
    nxpsc_lrp_inc_counter(c1, 4);
    bool res = (memcmp(c1, r1, 2) == 0);

    uint8_t c2[2] = {0x00, 0xF0};
    const uint8_t r2[2] = {0x01, 0x00};
    nxpsc_lrp_inc_counter(c2, 3);
    res = res && (memcmp(c2, r2, 2) == 0);

    uint8_t c3[2] = {0xFF, 0xF0};
    const uint8_t r3[2] = {0x00, 0x00};
    nxpsc_lrp_inc_counter(c3, 3);
    res = res && (memcmp(c3, r3, 2) == 0);
    return res;
}

static bool test_lrp_encode_decode(void) {
    nxpsc_lrp_ctx_t ctx;
    uint8_t out[128] = {0};
    size_t out_len = 0;

    const uint8_t key[16] = {0xE0, 0xC4, 0x93, 0x5F, 0xF0, 0xC2, 0x54, 0xCD,
                             0x2C, 0xEF, 0x8F, 0xDD, 0xC3, 0x24, 0x60, 0xCF
                            };
    const uint8_t counter[4] = {0xC3, 0x31, 0x5D, 0xBF};
    const uint8_t plain[16] = {0x01, 0x2D, 0x7F, 0x16, 0x53, 0xCA, 0xF6, 0x50,
                               0x3C, 0x6A, 0xB0, 0xC1, 0x01, 0x0E, 0x8C, 0xB0
                              };
    const uint8_t cipher[32] = {0xFC, 0xBB, 0xAC, 0xAA, 0x4F, 0x29, 0x18, 0x24,
                                0x64, 0xF9, 0x9D, 0xE4, 0x10, 0x85, 0x26, 0x6F,
                                0x48, 0x0E, 0x86, 0x3E, 0x48, 0x7B, 0xAA, 0xF6,
                                0x87, 0xB4, 0x3E, 0xD1, 0xEC, 0xE0, 0xD6, 0x23
                               };

    nxpsc_lrp_init(&ctx, key, 0, true);
    nxpsc_lrp_set_counter(&ctx, counter, sizeof(counter) * 2);

    bool res = (nxpsc_lrp_encode(&ctx, plain, sizeof(plain), out, sizeof(out), &out_len)
                == NXPSC_OK);
    res = res && (out_len == sizeof(cipher)) && (memcmp(out, cipher, sizeof(cipher)) == 0);

    nxpsc_lrp_init(&ctx, key, 0, true);
    nxpsc_lrp_set_counter(&ctx, counter, sizeof(counter) * 2);

    memset(out, 0, sizeof(out));
    res = res && (nxpsc_lrp_decode(&ctx, cipher, sizeof(cipher), out, sizeof(out), &out_len)
                  == NXPSC_OK);
    res = res && (out_len == sizeof(plain)) && (memcmp(out, plain, sizeof(plain)) == 0);
    return res;
}

static bool test_lrp_cmac(void) {
    nxpsc_lrp_ctx_t ctx;
    uint8_t mac[16] = {0};

    const uint8_t key1[16] = {0x81, 0x95, 0x08, 0x8C, 0xE6, 0xC3, 0x93, 0x70,
                              0x8E, 0xBB, 0xE6, 0xC7, 0x91, 0x4E, 0xCB, 0x0B
                             };
    const uint8_t data1[6] = {0xBB, 0xD5, 0xB8, 0x57, 0x72, 0xC7};
    const uint8_t res1[16] = {0xAD, 0x85, 0x95, 0xE0, 0xB4, 0x9C, 0x5C, 0x0D,
                              0xB1, 0x8E, 0x77, 0x35, 0x5F, 0x5A, 0xAF, 0xF6
                             };

    nxpsc_lrp_init(&ctx, key1, 0, true);
    nxpsc_lrp_cmac(&ctx, data1, sizeof(data1), mac);
    bool res = (memcmp(mac, res1, 16) == 0);

    const uint8_t key2[16] = {0x63, 0xA0, 0x16, 0x9B, 0x4D, 0x9F, 0xE4, 0x2C,
                              0x72, 0xB2, 0x78, 0x4C, 0x80, 0x6E, 0xAC, 0x21
                             };
    const uint8_t res2[16] = {0x0E, 0x07, 0xC6, 0x01, 0x97, 0x08, 0x14, 0xA4,
                              0x17, 0x6F, 0xDA, 0x63, 0x3C, 0x6F, 0xC3, 0xDE
                             };

    nxpsc_lrp_init(&ctx, key2, 0, true);
    nxpsc_lrp_cmac(&ctx, NULL, 0, mac);
    res = res && (memcmp(mac, res2, 16) == 0);
    return res;
}

static bool test_lrp_session_keys(void) {
    const uint8_t key[16] = {0};
    const uint8_t rnda[16] = {0x74, 0xD7, 0xDF, 0x6A, 0x2C, 0xEC, 0x0B, 0x72,
                              0xB4, 0x12, 0xDE, 0x0D, 0x2B, 0x11, 0x17, 0xE6
                             };
    const uint8_t rndb[16] = {0x56, 0x10, 0x9A, 0x31, 0x97, 0x7C, 0x85, 0x53,
                              0x19, 0xCD, 0x46, 0x18, 0xC9, 0xD2, 0xAE, 0xD2
                             };
    const uint8_t expected[16] = {0x13, 0x2D, 0x7E, 0x6F, 0x35, 0xBA, 0x86, 0x1F,
                                  0x39, 0xB3, 0x72, 0x21, 0x21, 0x4E, 0x25, 0xA5
                                 };

    uint8_t out[16] = {0};
    bool res = (nxpsc_session_key_lrp(key, rnda, rndb, true, out) == NXPSC_OK);
    res = res && (memcmp(out, expected, 16) == 0);
    return res;
}

static bool test_key_version(void) {
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
                      };
    nxpsc_des_key_set_version(key, NXPSC_KEY_2K3DES, 0xC7);
    return nxpsc_des_key_get_version(key) == 0xC7;
}

int nxpsc_selftest(bool verbose) {
    bool res = true;

    res = report("CRC search", test_crc_search(), verbose) && res;
    res = report("CMAC subkeys", test_cmac_subkeys(), verbose) && res;
    res = report("CMAC DES/2TDEA/3TDEA", test_cmac_tdes(), verbose) && res;
    res = report("AN10922 diversify", test_an10922(), verbose) && res;
    res = report("EV2 session keys", test_ev2_session_keys(), verbose) && res;
    res = report("EV2 IV", test_ev2_iv(), verbose) && res;
    res = report("EV2 MAC", test_ev2_mac(), verbose) && res;
    res = report("Trans session keys", test_trans_session_keys(), verbose) && res;
    res = report("LRP plaintexts", test_lrp_plaintexts(), verbose) && res;
    res = report("LRP eval", test_lrp_eval(), verbose) && res;
    res = report("LRP counter", test_lrp_counter(), verbose) && res;
    res = report("LRP encode/decode", test_lrp_encode_decode(), verbose) && res;
    res = report("LRP CMAC", test_lrp_cmac(), verbose) && res;
    res = report("LRP session keys", test_lrp_session_keys(), verbose) && res;
    res = report("DES key version", test_key_version(), verbose) && res;

    return res ? NXPSC_OK : NXPSC_E_CRYPTO;
}

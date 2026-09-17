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
// libnxpsc - NTAG 413 DNA / NTAG 424 DNA secure dynamic messaging (AN12196)
//-----------------------------------------------------------------------------

#include "nxpsc_internal.h"

#include <string.h>

// file option byte
#define SDM_AND_MIRRORING       (1 << 6)
// SDM option byte
#define SDM_OPT_UID             (1 << 7)
#define SDM_OPT_READ_CTR        (1 << 6)
#define SDM_OPT_READ_CTR_LIMIT  (1 << 5)
#define SDM_OPT_ENC_FILE_DATA   (1 << 4)
#define SDM_OPT_ASCII           (1 << 0)

// NTAG 4xx DNA application, ISO DF name
static const uint8_t ntag424_df_name[7] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};

static void put_u24(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFF);
    out[1] = (uint8_t)((value >> 8) & 0xFF);
    out[2] = (uint8_t)((value >> 16) & 0xFF);
}

int nxpsc_ntag424_select(nxpsc_card_t *card) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    int rc = nxpsc_iso_select_df_name(card, ntag424_df_name, sizeof(ntag424_df_name));
    if (rc == NXPSC_OK) {
        card->selected_aid = 0x000001;
        nxpsc_reset_channel(card);
    }
    return rc;
}

// serialises ChangeFileSettings, the SDM offsets are conditional on the access
// rights and option flags, see AN12196 table 69
int nxpsc_sdm_build_settings(nxpsc_commmode_t comm, const nxpsc_access_t *access,
                             const nxpsc_sdm_settings_t *sdm,
                             uint8_t *out, size_t cap, size_t *out_len) {
    if (access == NULL || out == NULL || out_len == NULL) {
        return NXPSC_E_PARAM;
    }
    if (cap < 3) {
        return NXPSC_E_LENGTH;
    }

    uint8_t options = 0;
    switch (comm) {
        case NXPSC_COMM_MAC:
            options = 0x01;
            break;
        case NXPSC_COMM_FULL:
            options = 0x03;
            break;
        default:
            break;
    }

    bool enabled = (sdm != NULL) && sdm->enabled;
    if (enabled) {
        options |= SDM_AND_MIRRORING;
    }

    uint16_t raw = nxpsc_pack_access(access);

    size_t off = 0;
    out[off++] = options;
    out[off++] = (uint8_t)(raw & 0xFF);
    out[off++] = (uint8_t)((raw >> 8) & 0xFF);

    if (enabled == false) {
        *out_len = off;
        return NXPSC_OK;
    }

    uint8_t sdm_options = SDM_OPT_ASCII;
    if (sdm->uid_mirror) {
        sdm_options |= SDM_OPT_UID;
    }
    if (sdm->counter_mirror) {
        sdm_options |= SDM_OPT_READ_CTR;
    }
    if (sdm->read_counter_limit) {
        sdm_options |= SDM_OPT_READ_CTR_LIMIT;
    }
    if (sdm->enc_file_data) {
        sdm_options |= SDM_OPT_ENC_FILE_DATA;
    }

    uint8_t meta_read = sdm->meta_read_key & 0x0F;
    uint8_t file_read = sdm->file_read_key & 0x0F;
    uint8_t ctr_ret = sdm->counter_ret_key & 0x0F;

    // worst case is 3 + 3 + 7 offsets of 3 bytes
    if (cap < off + 3 + (7 * 3)) {
        return NXPSC_E_LENGTH;
    }

    out[off++] = sdm_options;
    // upper nibble of the first byte is reserved and set to 0x0F
    out[off++] = (uint8_t)(0xF0 | ctr_ret);
    out[off++] = (uint8_t)((meta_read << 4) | file_read);

    if ((sdm_options & SDM_OPT_UID) && meta_read == 0x0E) {
        put_u24(out + off, sdm->uid_offset);
        off += 3;
    }

    if ((sdm_options & SDM_OPT_READ_CTR) && meta_read == 0x0E) {
        put_u24(out + off, sdm->counter_offset);
        off += 3;
    }

    // encrypted PICC data mirroring, meta read is a real key number
    if (meta_read <= 0x04) {
        put_u24(out + off, sdm->picc_data_offset);
        off += 3;
    }

    if (file_read != 0x0F) {
        put_u24(out + off, sdm->mac_input_offset);
        off += 3;

        if (sdm_options & SDM_OPT_ENC_FILE_DATA) {
            put_u24(out + off, sdm->enc_offset);
            off += 3;
            put_u24(out + off, sdm->enc_length);
            off += 3;
        }

        put_u24(out + off, sdm->mac_offset);
        off += 3;
    }

    if (sdm_options & SDM_OPT_READ_CTR_LIMIT) {
        put_u24(out + off, sdm->read_counter_limit_value);
        off += 3;
    }

    *out_len = off;
    return NXPSC_OK;
}

int nxpsc_sdm_configure(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm,
                        const nxpsc_access_t *access, const nxpsc_sdm_settings_t *sdm) {
    uint8_t settings[64] = {0};
    size_t len = 0;

    int rc = nxpsc_sdm_build_settings(comm, access, sdm, settings, sizeof(settings), &len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    return nxpsc_change_file_settings_raw(card, file_no, settings, len);
}

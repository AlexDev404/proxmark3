# Notes on NTAG 424 DNA and secure dynamic messaging
<a id="top"></a>

NTAG 413 DNA and NTAG 424 DNA use the DESFire command set, so almost the whole
DESFire part of the API applies unchanged. What is specific is the fixed file
layout and secure dynamic messaging.

## Table of Contents
- [Selecting the application](#selecting-the-application)
- [File layout](#file-layout)
- [Secure dynamic messaging](#secure-dynamic-messaging)
- [Verifying a tap on the server](#verifying-a-tap-on-the-server)

## Selecting the application
^[Top](#top)

`nxpsc_ntag424_select()` issues the ISO 7816-4 select of DF name
`D2760000850101`, the NDEF application. After that, authenticate with
`NXPSC_CHAN_EV2` and one of the five AES keys.

## File layout
^[Top](#top)

| File | Purpose | Size |
|---|---|---|
| `0x01` | capability container | 32 bytes |
| `0x02` | NDEF message, the file SDM mirrors into | 256 bytes |
| `0x03` | proprietary, full enciphered access only | 128 bytes |

## Secure dynamic messaging
^[Top](#top)

SDM makes the tag rewrite parts of the NDEF message on every read: the UID, a
read counter, and a CMAC over them. A phone reading the tag therefore opens a
URL that is different and unforgeable each time, with no app involved.

`nxpsc_sdm_build_settings()` serialises the AN12196 settings block. Its layout is
conditional, offsets are only present when the matching option selects them, so
build it with the helper rather than by hand:

- `UIDOffset` and `SDMReadCtrOffset` only when the meta read access is `0x0E`,
  that is plain PICC data
- `PICCDataOffset` only when the meta read access is a real key number
- `SDMMACInputOffset`, `SDMENCOffset` with `SDMENCLength`, and `SDMMACOffset`
  only when the file read access is not `0x0F`
- `SDMReadCtrLimit` only when its option bit is set

`nxpsc_sdm_configure()` sends the result with `ChangeFileSettings` in full
enciphered mode, which is the only mode the card accepts for it.

## Verifying a tap on the server
^[Top](#top)

The server repeats what the card did: derive the session keys from the SDM meta
read key and the read counter, decrypt the PICC data to recover the UID and
counter, then recompute the CMAC over the mirrored text. libnxpsc exposes the
same primitives used on the card side, so the verifier can be built on it
without a reader attached.

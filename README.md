# libnxpsc

A portable, backend agnostic C library for low level programming of NXP
smartcards.

| family | products |
| --- | --- |
| DESFire | MF3ICD40, EV1, EV2, EV2 XL, EV3, Light |
| MIFARE Plus | EV1, EV2 (SL1 and SL3) |
| NTAG | 413 DNA, 424 DNA (and TT) |
| DUOX | DUOX |

The library speaks the card protocols only. It never opens a reader itself, the
caller supplies a single transceive callback, so the same code runs on top of
libnfc, PC/SC, Android `IsoDep` through JNI, a Node N-API addon, or a bare metal
NFC frontend driver.

## What it does

- card identification from `GetVersion`, including the product table above
- every authentication flavour: legacy D40, ISO 3DES, AES EV1, EV2 first and
  non first, and LRP for EV2 XL / DESFire Light / NTAG 424
- application and file management, delegated applications, MIFARE Classic
  mapping, transaction MAC files, key sets, proximity check
- key change on any key including the PICC master key and factory key
  replacement, with AN10922 diversification
- NTAG 424 secure dynamic messaging, MIFARE Plus SL1 and SL3
- value files, records, backup files and the full transaction flow

## Build

```
cmake -S . -B build
cmake --build build
(cd build && ctest --output-on-failure)
```

See [docs/README.md](docs/README.md) for the full documentation, the transport
backend guide and the personalisation workflows.

## Licence

GPLv3, see [LICENSE.txt](LICENSE.txt).

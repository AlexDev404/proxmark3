# libnxpsc

A portable, backend agnostic C library for low level programming of NXP
smartcards.

| family | products |
| --- | --- |
| DESFire | MF3ICD40, EV1, EV2, EV2 XL, EV3, Light |
| MIFARE Plus | EV1, EV2 (SL1 and SL3) |
| NTAG | 413 DNA, 424 DNA (and TT) |
| DUOX | DUOX |

That table is what the code targets, not what has been proven against silicon.
Only DESFire EV3 has been run on a card. See
[Validation status](#validation-status) before relying on any of the others.

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

## Validation status

Three different things get called "supported", and the difference matters more
here than usual, so they are kept apart.

- **written** - the code exists and follows the references in
  [docs/md/Development/Porting_Notes.md](docs/md/Development/Porting_Notes.md)
- **tested** - covered by the off-card suite, which drives the library against a
  mock card. 54 protocol assertions and 15 crypto known answer vectors, run on
  every build under both gcc and MSVC
- **proven** - run against a real card and seen to work

Everything in the product table is written. Most of it is tested. One product is
proven.

### By card family

| family | status |
| --- | --- |
| DESFire EV3 | **proven**, and the only one |
| DESFire EV1, EV2, EV2 XL, MF3ICD40 | written and tested, never on a card |
| DESFire Light | written and tested, never on a card. Also the only user of the LRP channel, which has never run |
| MIFARE Plus EV1 / EV2 | written and tested, never on a card. 13 public calls, the largest untried block in the library |
| NTAG 413 / 424 DNA | written and tested, never on a card |
| DUOX | written and tested, never on a card |

### By secure channel

The channels matter more than the family names, because they carry the crypto
and several families share one.

| channel | status |
| --- | --- |
| D40, the legacy handshake | proven, through the factory 2TDEA PICC key |
| EV1, `AuthenticateISO` | proven. An EV3 still answers `0x1A`, so the channel can be forced on the card in hand rather than waiting for an EV1. Doing that found it broken outright, twice over: see [hardware notes](docs/hardware-notes.md#the-ev1-channel-chains-its-iv-through-the-handshake) |
| EV2 | proven, through AES application keys |
| LRP | **never run.** Needs a DESFire Light, or LRP turned on elsewhere |

### By API surface

69 of the 99 public calls have run against a card. Of the rest: 13 are MIFARE
Plus, 3 are NTAG and SDM, 5 are `SetConfiguration` and deliberately untried
because its one way bits would cost the card, 4 are delegated applications and
MIFARE Classic mapping, and the remainder are pure helpers covered off card.

### Why proving a channel is not proving a family

A shared channel does not make a family safe, and there is a concrete example.
`GetDFNames` sent inside a session is harmless on EV3 and **permanently disables
an EV1**: the card answers the first continuation frame with `0xC1`, "PICC will
be disabled", and never works again. Same library code, same channel, opposite
outcome. That was found in a hardware note in another project, not by testing,
because the card that would have shown it was not on the desk.

So for EV1 and EV2 the honest position is that the crypto is proven and the card
behaviour is not.

### If another family is ever needed

Buy the card. An EV1 and an EV2 cost a few euros each and would confirm the
`GetDFNames` guard actually guards the card it was written for, which is the
single largest piece of untested risk. MIFARE Plus needs a Plus card and a
session's work, since none of SL3 has ever been exercised.

The hardware suites live alongside this repository: `Tessera` covers the paths a
normal application uses, `Crucible` the rest, in tiers by how recoverable a
mistake is. Together they are 156 assertions against a card. Everything they
established that is not in a data sheet is written down in
[docs/hardware-notes.md](docs/hardware-notes.md), including the several places a
reference implementation is wrong.

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

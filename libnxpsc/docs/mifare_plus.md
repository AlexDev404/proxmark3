# Notes on MIFARE Plus
<a id="top"></a>

MIFARE Plus EV1 and EV2 are covered at security level 3, where every block
access is AES authenticated and optionally enciphered.

## Table of Contents
- [Security levels](#security-levels)
- [Authentication](#authentication)
- [Reading and writing](#reading-and-writing)
- [Value blocks](#value-blocks)
- [Personalisation](#personalisation)

## Security levels
^[Top](#top)

| Level | Behaviour |
|---|---|
| SL0 | factory state, keys are written with `WritePerso`, no security |
| SL1 | behaves as a MIFARE Classic |
| SL2 | Classic with an AES authentication on top, EV1 only |
| SL3 | AES only, the level libnxpsc speaks |

A card leaves SL0 for its target level with `CommitPerso`. That step is one way,
so write every key you will ever need before committing.

## Authentication
^[Top](#top)

`nxpsc_plus_authenticate()` performs the AES first or following authentication.
Plus key numbers are 16 bit, not 8 bit: sector keys are `0x4000 + 2*sector` for
key A and `+1` for key B, the card master key is `0x9000`, the configuration key
`0x9003`, and the AES sector keys of an SL3 card live in the `0x40xx` range.

The session derives an encryption key, a MAC key, a transaction identifier and
read and write command counters. Those counters are part of every MAC, so a lost
answer means the session must be restarted with `nxpsc_reset_channel()`.

## Reading and writing
^[Top](#top)

`nxpsc_plus_read()` and `nxpsc_plus_write()` take a block number, a block count
and flags selecting whether the data is enciphered and whether the card has to
return a MAC. Blocks are 16 bytes.

## Value blocks
^[Top](#top)

`nxpsc_plus_value_op()` performs increment and decrement into the transfer
buffer, and `nxpsc_plus_transfer()` writes that buffer back to a block.
As on a Classic card, nothing is durable until the transfer.

## Personalisation
^[Top](#top)

`nxpsc_plus_write_perso()` writes a key or a configuration block while the card
is still in SL0, `nxpsc_plus_commit_perso()` locks the result in. A typical
issuing sequence writes the card master key, the configuration key, the sector
keys, and then commits.

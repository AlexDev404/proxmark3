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
- [Level 1 configuration and virtual cards](#level-1-configuration-and-virtual-cards)

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

`nxpsc_plus_reset_auth()` sends `0x78`, which ends the session on the card. The
library drops its own session state with it, so the next operation has to
authenticate again. Use it to release a card cleanly rather than walking away
from an open session.

## Value blocks
^[Top](#top)

`nxpsc_plus_value_op()` performs increment and decrement into the transfer
buffer, and `nxpsc_plus_transfer()` writes that buffer back to a block. As on a
Classic card, nothing is durable until the transfer.

Two shortcuts avoid the second round trip:

| Call | Opcodes | Effect |
|---|---|---|
| `nxpsc_plus_value_transfer()` | `0xB7` / `0xB9`, `^0x02` when plain | increment or decrement and transfer in one command |
| `nxpsc_plus_restore()` | `0xC3` | load a block back into the transfer buffer, undoing an uncommitted change |

A terminal that debits a purse should prefer `nxpsc_plus_value_transfer()`: one
command means one place where a card can be torn from the field.

## Personalisation
^[Top](#top)

`nxpsc_plus_write_perso()` writes a key or a configuration block while the card
is still in SL0, `nxpsc_plus_commit_perso()` locks the result in. A typical
issuing sequence writes the card master key, the configuration key, the sector
keys, and then commits.

`nxpsc_plus_personalize_uid()` sends `0x40`, selecting how the card presents its
UID: the real one, a random one, or a single size one. Decide this before
committing, privacy requirements are hard to retrofit.

## Level 1 configuration and virtual cards
^[Top](#top)

`nxpsc_plus_set_config_sl1()` sends `0x44`, the security level 1 configuration
block, whose payload is defined by the card manual and passed through unchanged.

`nxpsc_plus_vc_support_last_iso_l3()` sends `0x4B`, which asks the card whether
it answered the last ISO level 3 command. Virtual card deployments use it to
decide which of several card representations the reader is talking to.

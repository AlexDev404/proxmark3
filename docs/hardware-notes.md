# Hardware notes
^[Top](#top)

Behaviour established against real silicon, not taken from a data sheet. Every
entry here was reached by sending the command to a card and reading what came
back, usually because a reference implementation disagreed with another one or
did not implement the command at all.

The card under test throughout is a DESFire EV3, `hw 33.00 sw 03.00`, production
week 08 of 2024, in factory state. Where a claim is specific to that silicon it
says so.

- [Why this file exists](#why-this-file-exists)
- [Statuses that are not errors](#statuses-that-are-not-errors)
- [A card error ends the session](#a-card-error-ends-the-session)
- [Legacy authentication and the DES degraded key](#legacy-authentication-and-the-des-degraded-key)
- [CreateApplication](#createapplication)
- [Key sets](#key-sets)
- [Records](#records)
- [Files in an ISO application](#files-in-an-iso-application)
- [Transaction MAC files](#transaction-mac-files)
- [The proximity check](#the-proximity-check)
- [NV memory is not reclaimed](#nv-memory-is-not-reclaimed)
- [Reference implementations](#reference-implementations)

## Why this file exists
^[Top](#top)

Several of the behaviours below are not in any reference implementation we could
find, and two of them are places where a reference implementation is wrong. A
developer reading only the code would reasonably assume the opposite of what the
card does, so the reasoning is written down rather than left in commit messages.

## Statuses that are not errors
^[Top](#top)

`0x00` is not the only success. The library also treats `0x90` as one, and the
proximity check depends on it: `PreparePC` answers `0x90` rather than `0x00`, and
the MAC the card returns at the end is computed over that `0x90`. Treating it as
an error stops the exchange before the first round.

`0x0B` is not in the status table and is not a failure of the command that
received it. It means the card is in proximity check mode. See
[The proximity check](#the-proximity-check).

## A card error ends the session
^[Top](#top)

Whenever the PICC answers an in-session command with an error status, it throws
the secure messaging session away. The reader does not find out except by
noticing that everything afterwards fails, and the failures are misleading: the
library kept appending MACs the card then read as trailing garbage, so a command
that was perfectly well formed came back `0x7E`, a length error.

`0x7E` rather than `0x1E` is what identifies this. A stale command counter would
fail the MAC and draw an integrity error; a length error means the card parsed
the frame as a plain command and found extra bytes on the end.

`nxpsc_exchange()` now drops the session on any status that is not `0x00`, `0x90`
or `0xAF`, and any later command that needs the session fails with
`NXPSC_E_AUTH` before anything reaches the wire. `nxpsc_session_lost()` tells a
caller that this is what happened, rather than the card refusing the command.

The practical consequence for callers: a command that draws an expected error,
for example probing whether a file exists, costs the session. Authenticate again
before carrying on.

## Legacy authentication and the DES degraded key
^[Top](#top)

A 2TDEA key whose two halves are equal is a single DES key. DESFire stores both
under the same key type nibble and tells them apart by comparing the halves, so
for such a key it derives the 8 byte DES session key rather than the 16 byte
2TDEA one.

The factory PICC master key is all zero, so this is the common case, not a corner
one. The handshake cannot expose the difference, because 3DES with `K1 == K2` is
single DES and the final check runs against the master key rather than the
session key. The first command on the session is where it shows up, and it shows
up as a decode failure with no obvious cause.

`nxpsc_authenticate()` mirrors the rule. Proxmark3 leaves it to the user, which
is why its documented incantation for a factory card is `-t des` rather than
`-t 2tdea`.

## CreateApplication
^[Top](#top)

The payload, in the order the card wants it:

```
AID(3) KeySett1 KeySett2 [KeySett3] [AKSVersion NoKeySets MaxKeySize AppKeySetSett]
      [ISOFileID(2) ISODFName(1..16)]
```

`KeySett2` bit 4 announces `KeySett3`. `KeySett3` bit 0 announces the four key
set bytes, bit 1 asks for application specific virtual card keys, bit 2 for
specific capability data. The key set block sits **before** the ISO fields, not
after them.

Constraints the card enforces:

| Field | Accepted |
|---|---|
| `NoKeySets` | 2 to 16 |
| `MaxKeySize` | 16 or 24 |
| `AppKeySetSett` | 3 bits, so 0 to 7. `0x0F` is refused with `0x9E` |

`nxpsc_create_application_ex()` reaches all of it. The two older calls are thin
wrappers and frame exactly as they did before.

On the EV3 tested, asking for specific VC keys is refused with `0x9D`: the PICC
does not allow it in its factory configuration. Turning virtual card support on
is a `SetConfiguration` path.

## Key sets
^[Top](#top)

An application only accepts the key set commands when it was created with
`num_key_sets >= 2`. Before that was reachable the whole feature was dead code,
and the documentation described a workflow nobody could run.

**`InitializeKeySet`'s second byte is the new set's key type**, carried
unshifted, so `0x00` is 2TDEA, `0x01` is 3TDEA and `0x02` is AES. This is the
trap in the whole feature: `0x00` is accepted inside an AES application and
quietly builds a 2TDEA key set, which then takes 2TDEA shaped `ChangeKeyEV2`
payloads and can never be rolled. Everything downstream then looks subtly broken
for reasons that have nothing to do with the command you are debugging.

`ChangeKeyEV2` into a key set works exactly as it does for the active set. AES
keys carry a version byte wherever they are written.

`RollKeySet` takes one byte, the target set. Two bytes answer `0x7E`, and the
active set answers `0x9E` because it is already active. It has to be issued
under the key the `AppKeySetSett` low nibble names; any other key answers `0xAE`.

The roll swaps out the key the running session was built from, so **the card
answers it without a MAC** and the session is gone afterwards. Asking for a MACed
answer turns a command the card carried out into a local length error, which
looks like a refusal and is not one. `nxpsc_roll_key_set()` asks for a plain
answer and resets the channel.

## Records
^[Top](#top)

Two things about record files that are easy to get backwards, and a test that
pins only one of them will pass on the wrong behaviour.

A record file holds **one pending record per transaction**. Writing twice before
a commit rewrites the same pending record rather than making two, so two records
means two commits.

Record numbers count back from the newest, so record 0 is the most recently
written. But a **multi record read returns the span oldest first**, so asking for
two records starting at 0 gives the older one first.

## Files in an ISO application
^[Top](#top)

An application created with an ISO file id makes one mandatory for every file
inside it. Asking for a file without one builds a frame two bytes shorter than
the card expects and it answers `0x7E`. The library frames the ISO field when
`iso_fid` is non zero, so it does what it is told; it has no way to know what the
application requires.

## Transaction MAC files
^[Top](#top)

`CommitReaderID` is switched on through the TMAC file's **ReadWrite access
right**, not through a separate option: `0x0F` disables it, `0x0E` is free
access, `0x00` to `0x04` names a key. A TMAC file created with ReadWrite `0x0F`
answers `0x9D` to `CommitReaderID`, which reads like a missing feature and is the
file's own settings refusing it.

`NotifyTransactionSuccess` answers `0x1C` on EV3. The command is not implemented
there.

## The proximity check
^[Top](#top)

The exchange runs, the MAC does not verify, and the reason is the key rather than
the construction.

What the card does:

- `PreparePC` answers status `0x90` and four bytes: Option `0x01`, a two byte
  published response time `0x0320`, and PPS1 `0x0A`. **Bit 0 of Option** is what
  says the PPS1 byte is present, not the response length
- the challenge is split evenly across the rounds, so only round counts that
  divide 8 are meaningful
- it is application scoped. At PICC level `PreparePC` answers `0x0B`

The MAC input is `0xFD || Option || pubRespTime || PPS1` followed, per round, by
the card's answer and then ours, with the first byte replaced by `0x90` to check
the card's reply. This matches LogicalAccess byte for byte and is **not** what
needs changing. 456 combinations of truncation, interleaving and header layout
were tried against two captured exchanges without reproducing the card's MAC.

The card MACs with its **VC Proximity Key, key `0x21`** of the application, which
an application only owns when created with specific VC keys. That is refused on a
factory EV3, so the MAC cannot currently be verified on this hardware.
`nxpsc_proximity_check()` reports the mismatch through `mac_ok` rather than
claiming the check passed.

**`PreparePC` leaves the card in proximity check mode**, where every other command
answers `0x0B` until the sequence finishes or the field drops. PC/SC disconnects
leave the card powered, so this outlives the process and poisons the next run.
Reset the card after a proximity check, with `SCardReconnect` and
`SCARD_RESET_CARD` or the equivalent.

## NV memory is not reclaimed
^[Top](#top)

DESFire frees the AID when an application is deleted but not the non volatile
memory behind it. A card that is repeatedly provisioned and wiped keeps losing
free memory until `CreateApplication` starts answering `0x0E`. Measured on EV3, a
run creating one application with six files costs 544 bytes of 5120; partial runs
cost less. `FormatPICC` is the only command that gives it back, and the
`nxpsc_reclaim` example does exactly that.

## Reference implementations
^[Top](#top)

Where they disagree, the card decides. What each one is good for, and see
[Where the protocol knowledge came from](md/Development/Porting_Notes.md) for
licences and the full list:

| Implementation | Covers | Notes |
|---|---|---|
| proxmark3 | Most of the command set | No key set commands. Its file settings decoder is where the TMAC reader id rule came from |
| libfreefare | Legacy and EV1 | No key sets |
| RevK DESFireAES | AES basics | Basic `CreateApplication` only, no ISO fields, no key sets |
| [dumacp/smartcard](https://github.com/dumacp/smartcard) (Go) | EV2 including key sets | Confirms the `CreateApplication` key set block and the key type constants |
| [liblogicalaccess](https://github.com/liblogicalaccess/liblogicalaccess) | EV2 including key sets and the proximity check | The only one with a proximity check. Note `createDelegatedApplicationParam` swaps the meanings of `KeySett3` bits 1 and 2 relative to `createApplication` |
| [springcard-dotnet-libraries](https://github.com/springcard/springcard-dotnet-libraries) | Virtual card and proximity check | Reader manufacturer for this silicon. Its `VerifyPC` MAC input contradicts its own comment, omitting Option and using the measured rather than published response time. The card cannot know a reader's measured time, so the comment is right and the code is not. Licence permits redistribution only with SpringCard hardware, so it is read as a reference and nothing is taken from it |

^[Top](#top)

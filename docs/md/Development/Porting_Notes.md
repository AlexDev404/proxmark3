# Where the protocol knowledge came from
<a id="top"></a>

libnxpsc was written by cross referencing four independent implementations. This
page records what each contributed, where they disagree, and which side won.

| Project | Language | Licence | Used for |
|---|---|---|---|
| [proxmark3](https://github.com/RfidResearchGroup/proxmark3) | C | GPLv3 | primary reference. EV2 and LRP secure messaging, ChangeKey rules, transaction MAC, SDM, MIFARE Plus SL3, and the known answer test vectors |
| [libfreefare](https://github.com/nfc-tools/libfreefare) | C | LGPLv3 with linking exception | legacy D40 and EV1 command formats, file and application semantics, the shape of a usable DESFire API |
| [python-desfire](https://github.com/waza-ari/python-desfire) | Python | MIT | independent check on command payloads and status handling |
| [DESFireAES](https://codeberg.org/RevK/DESFireAES) | C | GPLv3 | independent check on AES session key derivation and CMAC handling |

The implementation in this repository is new code, written against these
references rather than copied from them; the parts closest in structure follow
the proxmark3 implementation, which is GPLv3, as is this library.

## Disagreements found while cross referencing

- **AuthenticateEV2NonFirst opcode.** python-desfire uses `0x72`. The correct
  value is `0x77`; `0x72` is the MIFARE Plus AuthenticateContinue. The other
  three implementations agree on `0x77`.
- **Status `0x40`.** DESFireAES labels it as a generic error. It is
  `NO_SUCH_KEY`.
- **AN10922 key version.** An early version of this library applied the DES key
  version to the *derived* key. It must not be: the version is a property of the
  key as loaded into the card, not part of the derivation. The known answer
  vectors caught it.
- **ChangeKey checksums.** The three legacy behaviours differ and all are real:
  D40 appends CRC16 over the payload, and a second CRC16 over the new key when
  the key being changed is not the session key; EV1 appends CRC32 over
  `cmd || keyno || payload` plus a CRC32 over the new key in the same case;
  EV2 and LRP append only the CRC32 over the new key.
- **Single DES on the wire.** A single DES key travels as a 2K3DES key with both
  halves equal. libfreefare makes this explicit, the others hide it.
- **PICC master key type.** Encoded in the top bits of the key number byte, not
  in a separate field.

## Gap analysis against the references

Every DESFire opcode that proxmark3 defines is implemented or wrapped here,
including the ones proxmark3 itself only defines: delegated application
management, MIFARE Classic mapping, `RestrictMFCUpdate` and
`NotifyTransactionSuccess`. The MIFARE Plus command table is likewise complete
for security level 3 plus the SL0 and SL1 personalisation commands.

Where a command's payload is entirely card specific, the library takes a raw
buffer rather than pretending to understand it. Those are marked "payload per
card manual" in the header.

## Unverified areas

- The AES256 path of AN10922 has no published test vector. The construction
  follows the note, but is not covered by a known answer test.
- `nxpsc_session_key_lrp()` ignores its encryption key argument, which matches
  the proxmark3 behaviour and the note, but is worth re-reading if LRP ever
  misbehaves on hardware.

^[Top](#top)

# libnxpsc documentation
<a id="top"></a>

libnxpsc is a portable C library for low level programmatic control of NXP
contactless smartcards. It speaks the card protocol and nothing else, so it can
be driven by any NFC backend that can move an ISO 14443-4 payload.

Supported card families:

| Family | Values of `nxpsc_cardtype_t` | Notes |
|---|---|---|
| DESFire | `DESFIRE_MF3ICD40`, `DESFIRE_EV1`, `DESFIRE_EV2`, `DESFIRE_EV2_XL`, `DESFIRE_EV3` | full application, file, key and transaction support |
| DESFire Light | `DESFIRE_LIGHT` | AES and LRP secure messaging |
| MIFARE Plus | `PLUS_EV1`, `PLUS_EV2` | security level 3, personalisation and value blocks |
| NTAG DNA | `NTAG413DNA`, `NTAG424` | DESFire command set plus SDM mirroring |
| DUOX | `DUOX` | EV2 / LRP secure messaging |

## Table of contents

### Start here
- [Compilation instructions](md/Use_of_libnxpsc/0_Compilation-Instructions.md)
- [Validation](md/Use_of_libnxpsc/1_Validation.md)
- [Transport backends](md/Use_of_libnxpsc/2_Transport-Backends.md)
- [Personalisation workflows](md/Use_of_libnxpsc/3_Personalisation-Workflows.md)
- [Advanced compilation parameters](md/Use_of_libnxpsc/4_Advanced-compilation-parameters.md)

### Installation
- [Linux](md/Installation_Instructions/Linux-Installation-Instructions.md)
- [Windows](md/Installation_Instructions/Windows-Installation-Instructions.md)
- [macOS](md/Installation_Instructions/macOS-Installation-Instructions.md)

### Card notes
- [Hardware notes](hardware-notes.md) - behaviour established against real
  silicon, including the places a reference implementation is wrong
- [DESFire](desfire.md)
- [EV2 and later extras](advanced.md)
- [MIFARE Plus](mifare_plus.md)
- [NTAG 424 DNA and secure dynamic messaging](ntag424.md)

### Development
- [Architecture](md/Development/Architecture.md)
- [Contributing](md/Development/Contributing.md)
- [Coding style](md/Development/Coding_Style.md)
- [Where the protocol knowledge came from](md/Development/Porting_Notes.md)

### Reference
- [The Unofficial DESFire Bible](reference/unofficial_desfire_bible.md) - card side
  protocol reference, independent of any implementation

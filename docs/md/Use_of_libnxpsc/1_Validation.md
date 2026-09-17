# 1. Validation
<a id="top"></a>

## Run the test suite

```
cd build && ctest --output-on-failure
```

Two suites run, neither needs hardware.

### crypto

`nxpsc_test_crypto` runs `nxpsc_selftest()`, a set of known answer tests:

- CMAC subkey generation and CMAC over DES, 2TDEA and 3TDEA, NIST SP 800-38B
- AN10922 diversification for AES128, 2TDEA and 3TDEA
- EV2 session key derivation, IV construction and command MACs
- transaction MAC session keys
- the whole LRP construction of AN12304: plaintexts, evaluation, counter,
  encode, decode, CMAC and session keys
- DESFire CRC16 and CRC32 padding search, and DES key versioning

The same function is exported as `nxpsc_selftest()` so an application can assert
the library is sane before it touches a card, which the example does.

### protocol

`nxpsc_test_protocol` drives the library against a mock card transport. The mock
answers `GetVersion` for each supported family, so the suite checks, per family:

- that the card is identified as the right `nxpsc_cardtype_t`
- that the secure channel picked by `NXPSC_CHAN_AUTO` is the expected one
- the exact bytes put on the wire for native and ISO wrapped command sets
- 0xAF chaining of long answers
- NTAG 424 SDM settings serialisation, with and without SDM enabled
- MIFARE Plus personalisation framing, plus value transfer, restore, reset auth,
  SL1 configuration, UID personalisation and virtual card support
- ISO chained file access opcodes, and `UpdateRecord` field layout
- key set init, finalize and roll
- delegated application creation, including the command chaining of its 57 byte
  payload, and the parsing of `GetDelegatedInfo`
- transaction MAC file creation framing
- a full proximity check run: the mock computes the same AES CMAC from the same
  interleaved challenge, so a wrong card MAC is proven to be reported
- argument validation and the behaviour of commands issued without a session

This is what lets CI state compatibility with a card family without owning one.
Real hardware checks remain the responsibility of whoever has the card.

## CI

`.github/workflows/libnxpsc.yml` builds and tests on Linux, macOS and Windows,
with gcc, clang and MSVC, plus a `-Wall -Wextra -Werror` job. The build must be
warning free on gcc and clang.

^[Top](#top)

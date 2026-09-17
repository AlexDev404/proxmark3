# Architecture
<a id="top"></a>

```
            application / binding
                     |
            include/nxpsc/nxpsc.h        the only public surface
                     |
   +---------+-------+--------+-----------+
   | desfire | advanced | ntag424 | plus   |   command modules
   +---------+-------+--------+-----------+
                     |
                  channel                  D40 / EV1 / EV2 / LRP messaging
                     |
                   core                    framing, chaining, identification
                     |
                  crypto                   DES/AES, CMAC, CRC, KDF, LRP
                     |
            nxpsc_transport_t              your reader backend
```

## Files

| File | Responsibility |
|---|---|
| `src/nxpsc_core.c` | native and ISO 7816-4 framing, 0xAF chaining, `GetVersion`, card type detection, status decoding |
| `src/nxpsc_channel.c` | authentication for all four secure channels, per command encode and decode |
| `src/nxpsc_crypto.c` | block ciphers, CBC, CMAC, CRC16/CRC32, DES key versions, AN10922, EV2 and LRP session keys |
| `src/nxpsc_desfire.c` | applications, files, keys, values, records, transactions, ISO access |
| `src/nxpsc_advanced.c` | delegated applications, MIFARE Classic mapping, transaction MAC files, key sets, proximity check, configuration wrappers |
| `src/nxpsc_ntag424.c` | DNA tag selection and the AN12196 SDM settings serialiser |
| `src/nxpsc_plus.c` | MIFARE Plus security level 3 |
| `src/nxpsc_selftest.c` | known answer tests, also shipped as `nxpsc_selftest()` |
| `third_party/mbedtls` | trimmed mbedtls, AES and DES block functions only |

## Principles

- **No I/O.** The library never opens a device, a socket or a file. Everything
  reaches the card through the transport callback.
- **No globals.** All state is in `nxpsc_card_t`, allocated by `nxpsc_open()`.
- **Flat C API.** No macros in the public header beyond constants, no structs
  with function pointers other than the transport, so bindings stay trivial.
- **Card semantics are not hidden.** Where the card manual defines a raw byte,
  such as key settings or a MIFARE Classic mapping payload, the library passes
  it through rather than inventing an abstraction that would lag the silicon.
- **Escape hatch.** `nxpsc_command()` sends any native opcode through the active
  secure channel, so a card feature the API does not wrap is still reachable.

## Adding a command

1. Put the opcode in `src/nxpsc_internal.h` next to its neighbours.
2. Implement it in the module that owns the command family.
3. Declare it in `include/nxpsc/nxpsc.h`.
4. Add a framing assertion to `tests/test_protocol.c`, and mock card behaviour
   in `tests/mockcard.c` if the command needs an answer.
5. If it introduces a new derivation, add a known answer test.

^[Top](#top)

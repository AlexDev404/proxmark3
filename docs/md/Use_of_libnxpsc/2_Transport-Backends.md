# 2. Transport backends
<a id="top"></a>

libnxpsc never talks to a reader. It hands a byte buffer to a callback you
provide and expects the card answer back. That is the whole coupling, which is
why the same build works behind libnfc, PC/SC, an Android phone, a Node addon or
a bare metal NFC frontend.

## The contract

```c
typedef struct {
    void *ctx;
    int (*transceive)(void *ctx, const uint8_t *tx, size_t txlen,
                      uint8_t *rx, size_t rxcap, size_t *rxlen);
    int (*get_uid)(void *ctx, uint8_t *uid, size_t uidcap, size_t *uidlen);
    int (*reselect)(void *ctx);
} nxpsc_transport_t;
```

- `transceive` is required. `tx` and `rx` carry the ISO 14443-4 INF field only:
  no start or end framing, no CRC, no I-block PCB, no chaining. Return
  `NXPSC_OK` and set `rxlen`, or a negative `nxpsc_error_t`.
- `get_uid` is optional, used by the diversification helpers and as the fallback
  of `nxpsc_get_card_uid()` when no session exists.
- `reselect` is optional, used by flows that need the card put back into a known
  state.
- `ctx` is opaque to the library and handed back to every callback. The struct
  contents are copied by `nxpsc_open()`, the `ctx` pointer must stay valid.

The library is reentrant: all state lives in the `nxpsc_card_t` returned by
`nxpsc_open()`, there are no globals, so several cards can be driven at once
from several threads as long as each card is used from one thread at a time.

## Mapping onto common backends

| Backend | Call to put inside `transceive` | Notes |
|---|---|---|
| libnfc | `nfc_initiator_transceive_bytes()` | select the target with `NFC_ISO14443A` first |
| PC/SC | `SCardTransmit()` with `SCARD_PCI_T1` | cannot send raw native frames, use `NXPSC_CMDSET_NATIVE_ISO` |
| Android | `IsoDep.transceive()` through JNI | the same restriction as PC/SC on some devices |
| Node.js | an N-API wrapper over `pcsclite` | the callback must be synchronous, marshal to a worker if needed |
| MCU | your PN532 / PN5180 / ST25R driver | whatever function exchanges one ISO 14443-4 block |
| Proxmark3 | the `hf 14a apdu` / raw exchange path | useful for bench work |

`examples/loopback.c` is a working transport that answers without hardware, and
is the shortest complete example of the shape.

## Command set and the APDU only backends

Readers reached through PC/SC or Android usually refuse anything that is not an
ISO 7816-4 APDU. Call

```c
nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);
```

and the library wraps every native command as `90 cmd 00 00 00` when there is
no data or `90 cmd 00 00 Lc data 00` when data is present, which every DESFire
from EV1 on accepts. Chaining then uses `61 xx` / `90 AF` instead of a bare
`AF`, which the library also handles.

## Error mapping

Return the library's own codes from your transport so the caller sees one error
space:

| Situation | Return |
|---|---|
| card removed, no answer | `NXPSC_E_TRANSPORT` |
| answer longer than `rxcap` | `NXPSC_E_LENGTH` |
| bad arguments | `NXPSC_E_PARAM` |

Card side errors are not transport errors. If the card answered, even with a
failure status, return `NXPSC_OK`; the library decodes the status and exposes it
through `nxpsc_last_status()`.

^[Top](#top)

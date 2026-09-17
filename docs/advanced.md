# EV2 and later extras
<a id="top"></a>

Commands beyond the classic DESFire set: multi issuer card management, MIFARE
Classic mapping, key sets, the relay attack countermeasure, and the two
configuration wrappers. Most of these exist only on EV2 and later, DESFire Light
and DUOX support a subset.

# Table of Contents
- [ISO chaining](#iso-chaining)
- [Transaction MAC files](#transaction-mac-files)
- [Delegated applications](#delegated-applications)
- [MIFARE Classic mapping](#mifare-classic-mapping)
- [Key sets](#key-sets)
- [Proximity check](#proximity-check)
- [Transaction notification](#transaction-notification)
- [Configuration wrappers](#configuration-wrappers)
- [Updating a record in place](#updating-a-record-in-place)

## ISO chaining
^[Top](#top)

EV2 added a second opcode for each file access command, using ISO 7816-4
chaining instead of the native `0xAF` style. Same payload, different opcode:

| Native | ISO chained | Command |
|---|---|---|
| `0xBD` | `0xAD` | ReadData |
| `0x3D` | `0x8D` | WriteData |
| `0xBB` | `0xAB` | ReadRecords |
| `0x3B` | `0x8B` | WriteRecord |
| `0xDB` | `0xBA` | UpdateRecord |

```c
nxpsc_set_iso_chaining(card, true);
```

Turn it on when the reader or middleware cannot do native chaining, and for
files larger than the native length field can address. `nxpsc_ntag424_select()`
enables it automatically, because the DNA tags only expose the chained opcodes.
`nxpsc_get_iso_chaining()` reads the flag back.

## Transaction MAC files
^[Top](#top)

A transaction MAC file makes the card produce a MAC over every committed
transaction, which the back office can verify offline. That is what turns a
value file into an auditable purse.

```c
nxpsc_create_transaction_mac_file(card, file_no, comm, &access, &tm_key, version);
```

The TM key travels enciphered, so the command is always sent in full mode and
needs an open session. During the transaction, `nxpsc_commit_reader_id()` binds
the terminal identity into the MAC and returns the previous reader id,
enciphered.

## Delegated applications
^[Top](#top)

Delegated application management lets a card owner hand a slot of the card to a
second issuer, who can create and manage their own application without the
owner's keys, within a memory quota.

```c
nxpsc_create_delegated_application(card, aid, dam_slot, dam_slot_version,
                                   quota_limit, key_settings, num_keys, key_type,
                                   iso_fid, df_name, df_name_len,
                                   enck, enck_len, dam_mac, dam_mac_len);
nxpsc_get_delegated_info(card, dam_slot, &info);
```

`enck` and `dam_mac` are produced by the DAM authority from its DAM keys, they
are not derived by the library; the card manual defines their construction. The
library sends the application data and the continuation data as one logical
command so the secure messaging state advances once.

`nxpsc_delegate_info_t` returns the slot version, the quota, the free blocks
left in the slot and the AID occupying it.

## MIFARE Classic mapping
^[Top](#top)

EV2 XL and EV3 can expose part of their memory as a MIFARE Classic sector, so
legacy infrastructure keeps working during a migration.

```c
nxpsc_create_mfc_mapping(card, data, len);      // sent enciphered, carries keys
nxpsc_restrict_mfc_update(card, data, len);     // narrows what the Classic side may change
```

Both take the raw payload from the card manual. The layout is card specific and
the library deliberately does not model it.

## Key sets
^[Top](#top)

An application can hold several complete sets of keys and switch between them
atomically, which is how a key rotation happens without a window where half the
estate is broken.

The application has to be built for them. A plain `nxpsc_create_application()`
cannot hold key sets and every command below will be refused on it, so reach for
`nxpsc_create_application_ex()` and give it `num_key_sets`:

```c
nxpsc_app_config_t cfg = {0};
cfg.key_settings = 0x0F;
cfg.num_keys = 3;
cfg.key_type = NXPSC_KEY_AES128;
cfg.num_key_sets = 4;        // sets 0..3, set 0 is the active one
cfg.max_key_size = 16;
nxpsc_create_application_ex(card, aid, &cfg);
```

```c
nxpsc_init_key_set(card, key_set, key_set_settings);     // create the set
nxpsc_change_key_ev2(card, key_set, key_no, old, new);   // fill it
nxpsc_finalize_key_set(card, key_set, key_set_version);  // freeze it
nxpsc_roll_key_set(card, key_set);                       // make it the active one
```

Roll is the switch. Until it is called the new set is inert, so a batch of cards
can be prepared over weeks and cut over in one pass.

Two things differ from the active set, both confirmed against EV3 rather than
taken from a reference implementation, since none of proxmark3, libfreefare or
RevK's DESFireAES implements key sets:

- `key_set_settings` is a settings byte, not a key count. The number of keys and
  their type come from the application. An EV3 whose `AppKeySetSett` is `0x00`
  accepts only `0x00` here, answering `0x9D` to `0x01` and `0x9E` to `0x80`
- a key in a non active set carries no version byte of its own, the set takes
  its version from `nxpsc_finalize_key_set()`. `nxpsc_change_key_ev2()` handles
  that, sending `key || CRC32(key)` for a non active set against
  `key || version || CRC32(key)` for the active one

## Proximity check
^[Top](#top)

The proximity check measures the round trip time of a random challenge to detect
a relay. It is the reason an attacker cannot simply tunnel a card from another
country into your terminal.

```c
bool mac_ok = false;
nxpsc_proximity_check(card, &pc_key, rounds, &mac_ok);
```

The library generates the 8 byte challenge, splits it over `rounds` exchanges,
1 to 8, collects the card answers, and computes the AES CMAC, truncated to its
odd bytes, over the interleaved challenge and response. `mac_ok` reports whether
the card's own MAC over the same input matched; it may be NULL if you do not
care. `rounds` of 8 gives the tightest timing resolution.

`PreparePC` ends any open authentication on the card, so the library drops its
side of the session too. Authenticate again afterwards.

## Transaction notification
^[Top](#top)

`nxpsc_notify_transaction_success()` sends `0xEE`, which ECP capable readers use
to tell the card a transaction completed, letting the card update its own state
and a phone show the transaction as done.

## Configuration wrappers
^[Top](#top)

Thin wrappers over `SetConfiguration`, all of which need an authenticated session
with the PICC master key:

| Call | Option | Effect |
|---|---|---|
| `nxpsc_set_picc_config()` | `0x00` | disable `FormatPICC`, enable random UID |
| `nxpsc_set_default_key()` | `0x01` | default key used for keys of applications created later |
| `nxpsc_set_ats()` | `0x02` | replace the ATS the card answers with |

Disabling format and enabling random UID are one way on most cards. Read the
card manual before sending either to a production batch.

## Updating a record in place
^[Top](#top)

```c
nxpsc_update_record(card, file_no, record_no, offset, data, len, comm);
```

Rewrites part of an existing record rather than appending a new one. Record 0 is
the most recent record. As with every record operation, the change only becomes
durable at `nxpsc_commit_transaction()`.

^[Top](#top)

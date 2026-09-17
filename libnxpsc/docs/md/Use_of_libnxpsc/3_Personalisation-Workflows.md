# 3. Personalisation workflows
<a id="top"></a>

What an issuing station does, in the order it does it. `examples/personalize.c`
is this page as compilable code.

## Table of Contents
- [Identify the card](#identify-the-card)
- [Replace the factory keys](#replace-the-factory-keys)
- [Diversify per card](#diversify-per-card)
- [Lay out the application](#lay-out-the-application)
- [Closed loop payment](#closed-loop-payment)
- [Ticketing](#ticketing)
- [Locking it down](#locking-it-down)

## Identify the card
^[Top](#top)

`nxpsc_get_version()` then `nxpsc_identify()`. Branch on the returned
`nxpsc_cardtype_t` rather than assuming, a production batch is rarely uniform
and an EV3 in an EV2 slot must not be personalised as an EV2.

## Replace the factory keys
^[Top](#top)

Cards ship with an all zero single DES PICC master key. Authenticate with it on
the legacy channel, then `nxpsc_change_key()` to the AES issuer key. The session
dies with the key it was opened with, so authenticate again afterwards.

Never ship a card with a factory key still in place, and never derive every card
from one static key.

## Diversify per card
^[Top](#top)

`nxpsc_diversify_an10922()` implements AN10922. Feed it the master key and a
diversification input that is unique per card and per application, conventionally
`UID || AID || system identifier`. The master key then never leaves the issuing
HSM or the back office, and a compromised card yields only its own keys.

The same call covers AES128, 2TDEA and 3TDEA; the derived key keeps the type of
the master key.

## Lay out the application
^[Top](#top)

`nxpsc_create_application()`, or `nxpsc_create_application_iso()` when an ISO
file id and DF name are wanted, then the file creation calls. Decide the access
rights before creating, since changing them later needs the change key and, for
some settings, is not possible at all.

## Closed loop payment
^[Top](#top)

Use a value file: `nxpsc_create_value_file()` with the lower and upper limits of
the purse and limited credit enabled if terminals may top up offline. Terminals
then use `nxpsc_debit()` and `nxpsc_limited_credit()` inside a transaction ended
by `nxpsc_commit_transaction()`.

Give the debit key and the credit key different key numbers, so a terminal that
only ever charges cannot also load value.

On EV2 and later add a transaction MAC file, so every commit produces a MAC the
back office can verify, and `nxpsc_commit_reader_id()` to bind it to the
terminal.

## Ticketing
^[Top](#top)

A backup data file holds the product, a value file or a cyclic record file holds
the rides or the log. Record files are the audit trail: `nxpsc_write_record()`
per use, `nxpsc_read_records()` to collect, `nxpsc_clear_record_file()` to reset
during re-issue.

Keep the whole tap inside one transaction so a card torn from the field leaves
either the old state or the new one, never half of each.

## Locking it down
^[Top](#top)

- set the application key settings so the master key can no longer be changed
  once the card is in the field, if the scheme allows it
- switch DESFire Light to LRP before issuing if the deployment requires it, it
  is one way
- for MIFARE Plus, write every key in SL0 and then `nxpsc_plus_commit_perso()`,
  which is also one way
- verify with a read back pass: re-select, re-authenticate with the diversified
  keys, and confirm the file settings the card reports match what was intended

^[Top](#top)

# Partial permission: hand-derived teaching notes

Exact authored file bytes are `LEFTPRIVATE\r\nRIGHTKNOWN!`, with no final newline.
Both data records are11 bytes. Their starts are0 and13. Only the first record has
a separator: CRLF at absolute offset11; the final empty separator is at24.

The sample artifact identifies ordinal0's whole-record source/framing/length/hash
but grants **only** its relative span `[4,8)`: bytes `PRIV`, hex `50524956`,
absolute offsets4–7. Knowing a RecordRef or its whole-record hash does not grant
its other bytes. No bytes of ordinal1 are sample-authorized.

Hand-derived scoped display expectation for ordinal0:

| Relative positions | Source bytes | Authorized diagnostic cells |
|---|---|---|
| 0–3 | LEFT | redacted/null |
| 4–7 | PRIV | P R I V /50 52 49 56 hex |
| 8–10 | ATE | redacted/null |

This is a permission illustration, not a generated grid capture. An actual
default page may start its bounded window at the first authorized byte4; a
detail request `[0,11)` includes masked prefix/suffix cells. Full-window raw_hex
cannot contain the concealed neighbors. Authorized views omit separator raw
bytes and partial-record reasons; the second row is omitted/not_authorized.
Prompts and explanation evidence must remain within `[4,8)`.

Owner-mode inspection intentionally may display all retained bytes. All bytes in
this example are public. No runtime privacy/isolation property is asserted from
the hand table or from the authorization label.

No status vocabulary or real business meaning is supplied. Unknown codes are not
automatically malformed, and these words do not determine account/date/balance
fields. Partial evidence may be insufficient to approve any full-row mapping;
there is no fabricated typed value, ruling, score or migration output.

# Reordered ledger: hand-derived teaching notes

This is public, deliberately known layout information, not a saved program result.
The brief lists concepts without widths, offsets, order, chosen scale or century.

Exact data records (display spaces with care):

```text
2402290042+001750NORTH  O
2403010043-000025SOUTH  C
```

Each record is25 bytes followed by LF. Starts are0 and26; LF offsets25 and51;
source length52. Both whole-record samples are explicitly authorized. No record
can be deduplicated based on identity-looking text. Framing-v2 descriptor in
pins.json is independently authored from these literal facts.

The author's teaching layout is date `[0,6)`, account_ref `[6,10)`, balance
`[10,17)`, description `[17,24)`, status `[24,25)`. This table is outside the
brief on purpose. It does not guarantee finite discovery offers the true boundary
or that a future question/answer succeeds.

Concrete decisions to inspect later:

- Are the adjacent digit spans a date plus leading-zero text identifier, or does
  the offered boundary miss this author layout? Choose unknown if absent.
- For `+001750`, scale0/2/3 would represent1750/17.50/1.750 under those respective
  declared arithmetic policies. This is hand arithmetic, not transformed output.
  `-000025` also needs an explicit leading-sign and scale interpretation.
- Six date digits alone do not choose a century window. A YYYYMMDD candidate
  would not fit the six-byte author span; an absent correct option stays unknown.
- Are the two trailing spaces declared right padding or preserved text? Do not
  trim by habit. Status vocabulary O/C is disclosed; generic character patterns
  alone do not establish any semantic name.

Hand expectation: frameable ASCII input and exact sample references can be
eligible. Hypotheses remain proposals; mapping is unconfirmed/incomplete until
authentic offered choices/required policies and coverage are resolved. No load,
target readback, parity, benchmark or acceptance result is supplied here.

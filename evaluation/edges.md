# Hand-calculated edge audit table

Source construction only. These expectations require a later independent audit;
this table is not executed test evidence.

Public corpus-v2 SOURCE covers all three signs, scales 0/2/3, both date formats
with explicit 1970–2069 windows, blank/all-nines sentinels, left/right/no padding,
both separators, terminal-newline absence and distinct-ordinal business duplicates.
Its six variants and ten-batch loops have not been executed or materialized.
Precision-seven values are serialized into eight zero-filled digit positions;
an eight-significant-digit malformed value intentionally overflows that policy.
The fixture encoder never decodes candidate output to obtain canonical values.

The eleven value/identity mutations and three lineage/load mutations now have
callable source in `mutation_audit.py`. A later audit must first establish an
exact positive control and independently inspect detection; no source assertion
in this document establishes a passed mutation suite.

| Edge | Declared policy/input | Required independent result |
|---|---|---|
| Leading zero | text ID `000001` | text `000001`, never integer 1 |
| Blank text | right-space trim of twelve spaces | empty string, distinct from NULL |
| Null/empty/zero | null date / empty text / decimal `0.00` | three distinct typed values |
| Negative zero | leading sign `-00000000`, scale 2 | decimal `0.00`, retain source lexeme evidence |
| Precision limit | precision 8 scale 2, `+99999999` | decimal `999999.99` |
| Overflow | precision 8, nine magnitude digits | quarantine precision_overflow |
| Sign/scale | trailing `00000123-`, scale 3 | decimal `-0.123` |
| Leap date | YYYYMMDD `20240229` | date `2024-02-29` |
| Invalid date | YYYYMMDD `20230229` | quarantine invalid_date |
| Ambiguous year | YYMMDD `240101`, no century window | unresolved policy, never invented century |
| Sentinel | explicit `99999999` -> null | typed date NULL; zero date remains invalid |
| Padding | declared right-space trim | trim only declared spaces; reject other declared-invalid padding |
| Framing | LF or CRLF consistent | exact byte offsets; separator excluded from raw hash |
| Final newline | absent, full record width | accepted with declared final-newline policy |
| Business duplicate | equal bytes at ordinals 6, 7 | two distinct RecordRefs and two rows |
| Changed byte | source or raw digest differs | extra/missing exact identity, no fuzzy repair |
| High byte | any raw byte > 127 | quarantine high_byte |
| Short record | length 35 vs width 36 | quarantine wrong_length |
| Wrong target | balance bytes named description | primary semantic mismatch regardless of slot correctness |
| Cancelling errors | one balance +1, another -1 | both rows fail even if sum unchanged |
| Empty oracle | zero supported records | rate null, parity incomplete |

Unsupported fixtures are separately declared in `fixtures/dev/unsupported.json`.
They are excluded from supported semantic denominators. The declaration exercises
an explicit refusal path; arbitrary encoding detection is not claimed.

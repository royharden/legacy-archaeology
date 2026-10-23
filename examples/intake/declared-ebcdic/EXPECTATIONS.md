# Declared unsupported format: hand-derived teaching notes

The literal bytes are ASCII `OPEN\nSHUT\n` (10 bytes). This is intentionally
**not** an actual EBCDIC corpus. Passing `--encoding EBCDIC` declares an excluded
format and should retain an explicit unsupported_encoding refusal. It tests the
declared-format boundary, not universal encoding detection.

There are two LF-observed records by hand. Declaration refusal happens before
normal record materialization: expected materialized0, unmaterialized2, width
unresolved. The refusal framing descriptor in pins.json is unresolved-v2 rather
than pretending this unsupported intake was accepted as a four-byte ASCII layout.
An empty records list must not be described as zero input or successful migration.

The sample artifact has no record authorizations. Its source/content pins do not
create a fake RecordRef or permission for unavailable framed rows. Small bounded
CLI input can retain the original source.dat even while refusing materialization;
this differs from oversize stream refusal, which cannot retain a complete source
within the configured memory limit and must never store a truncated prefix.

No hypothesis, mapping, question answer, transformed value, database load or
measured refusal output is shipped. Inspect the actual future refusal rather than
copying these teaching expectations into an execution receipt.

# Shared wire boundary source

The canonical strict Pydantic base is `la.contracts.base.Boundary`, re-exported
unchanged as `la.contracts.Boundary`. It forbids unknown outer fields, applies
strict types and checks supplied hash-shaped identities. It imports only
Pydantic. Child schema modules do not import the package root or producers.

`la.contracts.evidence` is the single owner of closed nested sample, span, intake
and discovery syntax. Public aliases are RecordIdentity, RecordDisplay,
SpanEvidence, PermittedSampleArtifact, SampleMetadata, IntakeMetadata and
DiscoveryMetadata. SourceBatch uses SampleMetadata/IntakeMetadata; Generation
uses DiscoveryMetadata; candidates and questions use SpanEvidence. Owner helper
functions validate_sample_artifact, validate_sample_metadata,
validate_intake_metadata, validate_span_evidence and validate_discovery_metadata
return deep copies containing exactly the supplied values/keys/list order.

Legacy sample metadata, framing versions, materialized intake and observed-only
refusal forms have explicit closed alternatives. Discovery supports empty,
profile-current, explicit-filler-only and documented public hand-declared forms.
An empty or omitted diagnostic does not authorize arbitrary keys. Unknown-count
observations preserve None and cannot materialize rows or sample permission.
Unknown protocol fields and bool-as-count values reject before prompting/approval.
Raw lexical strings remain inert data. Exact source/evidence authorization is
still resolved by the ingest owner; shape validation is not source authorization.

All nested aliases retain dictionary public APIs. `validate_batch` and
`validate_generation` serialize with `exclude_unset=True`; omitted optional
intake/discovery/filler remain absent. Supplied metadata participates in new
producer hashes. Nothing rehashes or rewrites preserved artifacts. Historical
arbitrary dictionaries that were never a documented producer wire are not a
compatibility alternative. New demo/test hand mappings declare their explicit
public information source and sample pins before calculating a new generation.

`la.contracts.protocol` closes only shared dictionary syntax for policy values,
finite options (including the exact unknown option), explicit filler spans and
row-outcome evidence/proposal attribution. It does not decide business meaning,
policy legality, conversion, coverage, product approval or target acceptance.
`la.review.policy.validate_policy` remains D5's business-policy authority. There
is no shared-schema import of review/converter/inference/provider roots.

`la.providers.wire` closes caller request metadata and provider settlement wrapper
fields. Known metadata cannot smuggle arbitrary dictionaries into call receipts.
External raw_usage is explicitly bounded opaque finite JSON, including cached,
reasoning and unsupported future vendor categories. It is never stripped or
normalized into a known charge. `priced_usage` alone decides supported pricing;
unsupported/missing usage remains unknown liability. Reconciliation IDs and pins
are exact typed values; old committed receipts are retained unchanged.

Target schemas, signed authority validation, target-effect/readback policies and
capture manifests remain D5-owned. Independent grading, signed T1 billing context
and T0/T2/T3 custody schemas remain D6-owned. Shared consumers use their actual
versioned constructors and validators; a supplied boolean never replaces concrete
public-key verification or an actual observed effect. Optional dependencies stay
lazy. The inference wheel excludes all evaluator/script code.

This is source construction in Dirty Mode. No model import, schema validation,
test collection/run, crypto, stream, provider or database operation was executed
to verify these statements. AST parsing and focused source inspection are the
available evidence; runtime behavior remains unverified.

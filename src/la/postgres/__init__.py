"""Offline bundle integrity and explicitly authorized PostgreSQL entrypoints."""
from la.convert.bundle import inspect_snapshot, verify_bundle, write_verification_receipt


def validate_bundle(bundle_path, *, expected_bundle_sha256=None, expected_source_sha256=None,
                    expected_mapping_sha256=None):
    """Compatibility tuple API; without external pins this is inspection, not authority."""
    snapshot = inspect_snapshot(bundle_path)
    if any(pin is not None for pin in (expected_bundle_sha256, expected_source_sha256, expected_mapping_sha256)):
        pins = {'bundle_sha256': expected_bundle_sha256, 'source_sha256': expected_source_sha256,
                'mapping_sha256': expected_mapping_sha256}
        if expected_bundle_sha256 is None or not snapshot.code_matches or not snapshot.input_closure or not snapshot.rows or any(value is not None and value != snapshot.manifest[key] for key, value in pins.items()):
            raise ValueError('bundle failed externally pinned verification')
    return (snapshot.manifest, snapshot.mapping, snapshot.rows,
            snapshot.ddl, snapshot.sql, snapshot.columns)


from .target import TargetConfig
from .execution import database_check, reconcile_commit, rollback_check, constraint_checks, write_execution_receipt, target_observer

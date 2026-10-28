"""Offline bundle integrity and explicitly authorized PostgreSQL entrypoints."""
from la.convert.bundle import inspect_snapshot, load_snapshot, verify_bundle, write_verification_receipt


def validate_bundle(bundle_path, *, expected_bundle_sha256=None, expected_source_sha256=None,
                    expected_mapping_sha256=None):
    """Compatibility tuple API; without external pins this is inspection, not authority."""
    if any(pin is not None for pin in (expected_bundle_sha256, expected_source_sha256, expected_mapping_sha256)):
        snapshot, _ = load_snapshot(bundle_path, expected_bundle_sha256=expected_bundle_sha256,
                                    expected_source_sha256=expected_source_sha256,
                                    expected_mapping_sha256=expected_mapping_sha256)
    else:
        snapshot = inspect_snapshot(bundle_path)
    return (snapshot.manifest, snapshot.mapping, snapshot.rows,
            snapshot.ddl, snapshot.sql, snapshot.columns)


from .target import TargetConfig
from .execution import database_check, reconcile_commit, rollback_check, constraint_checks, write_execution_receipt, target_observer
from .candidate import prepare_evaluation_candidate, prepare_evaluation_candidate_v2, observer_code_pin
from .authority import TargetAuthorityVerifier
from .runner import target_observer_v2, reconcile_target_candidate, collect_controlled_failed_load, collect_controlled_lost_ack, collect_controlled_ack_predecessor
from .effects import validate_target_observation, validate_negative_effect, write_target_observation, write_negative_effect
from .experiment import (collect_target_experiment, open_target_experiment,
                         target_experiment_callbacks, reconcile_target_experiment)

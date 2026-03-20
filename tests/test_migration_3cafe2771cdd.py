"""
Data transformation test for migration 3cafe2771cdd
Set empty rollout_state to 'enrolled' in token table

This migration updates all rows in the 'token' table where
  rollout_state = '' or rollout_state IS NULL
to
  rollout_state = 'enrolled'

upgrade()   — rewrites ''  → 'enrolled'  and  NULL → 'enrolled'
downgrade() — reverts  'enrolled'  → ''

Rows with other rollout_state values must be untouched in both directions.
"""

import os

import pytest

from tests.migration_test_utils import MigrationTestBase

pytestmark = [
    pytest.mark.migration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL environment variable is not set",
    ),
]

DB_URL = os.environ.get("TEST_DATABASE_URL", "")


def _make_token(serial: str, rollout_state: str | None) -> dict:
    """Return a minimal token row dict suitable for insertion into the token table."""
    return {
        "serial": serial,
        "tokentype": "HOTP",
        "active": True,
        "revoked": False,
        "locked": False,
        "otplen": 6,
        "maxfail": 10,
        "failcount": 0,
        "count": 0,
        "count_window": 10,
        "sync_window": 1000,
        "rollout_state": rollout_state,
    }


class TestMigration3cafe2771cdd(MigrationTestBase):
    REVISION = "3cafe2771cdd"
    PARENT_REVISION = "06b105a4f941"

    def _fetch_rollout_state(self, engine, serial: str) -> str | None:
        return self._fetch_scalar(
            engine,
            "SELECT rollout_state FROM token WHERE serial = :serial",
            {"serial": serial},
        )

    def test_upgrade_sets_empty_string_to_enrolled(self, flask_app):
        """upgrade() must rewrite rollout_state='' → 'enrolled'."""
        engine = self._engine()
        self._load_seed_and_upgrade_to_parent(engine)
        self._insert_rows(engine, "token", [_make_token("TOK001", "")])
        assert self._fetch_rollout_state(engine, "TOK001") == ""
        engine.dispose()

        self._upgrade()

        engine = self._engine()
        assert self._fetch_rollout_state(engine, "TOK001") == "enrolled", (
            "upgrade() must rewrite '' to 'enrolled' in token.rollout_state"
        )
        engine.dispose()

    def test_upgrade_sets_null_to_enrolled(self, flask_app):
        """upgrade() must rewrite rollout_state=NULL → 'enrolled'."""
        engine = self._engine()
        self._load_seed_and_upgrade_to_parent(engine)
        self._insert_rows(engine, "token", [_make_token("TOK002", None)])
        assert self._fetch_rollout_state(engine, "TOK002") is None
        engine.dispose()

        self._upgrade()

        engine = self._engine()
        assert self._fetch_rollout_state(engine, "TOK002") == "enrolled", (
            "upgrade() must rewrite NULL to 'enrolled' in token.rollout_state"
        )
        engine.dispose()

    def test_upgrade_leaves_clientwait_untouched(self, flask_app):
        """upgrade() must not modify rows where rollout_state='clientwait'."""
        engine = self._engine()
        self._load_seed_and_upgrade_to_parent(engine)
        self._insert_rows(engine, "token", [_make_token("TOK003", "clientwait")])
        engine.dispose()

        self._upgrade()

        engine = self._engine()
        assert self._fetch_rollout_state(engine, "TOK003") == "clientwait", (
            "upgrade() must not touch rows where rollout_state is 'clientwait'"
        )
        engine.dispose()

    def test_upgrade_leaves_already_enrolled_untouched(self, flask_app):
        """upgrade() must not modify rows that already have rollout_state='enrolled'."""
        engine = self._engine()
        self._load_seed_and_upgrade_to_parent(engine)
        self._insert_rows(engine, "token", [_make_token("TOK004", "enrolled")])
        engine.dispose()

        self._upgrade()

        engine = self._engine()
        assert self._fetch_rollout_state(engine, "TOK004") == "enrolled"
        engine.dispose()

    def test_downgrade_reverts_enrolled_to_empty_string(self, flask_app):
        """downgrade() must rewrite rollout_state='enrolled' → ''."""
        engine = self._engine()
        self._load_seed_and_upgrade_to_parent(engine)
        self._insert_rows(engine, "token", [_make_token("TOK005", "")])
        engine.dispose()

        self._upgrade()
        self._downgrade()

        engine = self._engine()
        assert self._fetch_rollout_state(engine, "TOK005") == "", (
            "downgrade() must revert 'enrolled' back to '' in token.rollout_state"
        )
        engine.dispose()

    def test_round_trip_preserves_other_rollout_states(self, flask_app):
        """An upgrade → downgrade round-trip must leave rows with other rollout_states unchanged."""
        engine = self._engine()
        self._load_seed_and_upgrade_to_parent(engine)
        self._insert_rows(engine, "token", [
            _make_token("TOK006", ""),
            _make_token("TOK007", "clientwait"),
            _make_token("TOK008", "pending"),
        ])
        engine.dispose()

        self._upgrade()
        self._downgrade()

        engine = self._engine()
        assert self._fetch_rollout_state(engine, "TOK007") == "clientwait", (
            "Round-trip must not corrupt rows with rollout_state='clientwait'"
        )
        assert self._fetch_rollout_state(engine, "TOK008") == "pending", (
            "Round-trip must not corrupt rows with rollout_state='pending'"
        )
        engine.dispose()

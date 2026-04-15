"""v3.14: Mark u2f tokens as deprecated

Flip rows with tokentype='u2f' to tokentype='deprecated', stash the
original type and active state in tokeninfo, and mark the tokens
inactive. See dev/token-deprecation-strategy.md for the full design.

upgrade() creates three tokeninfo marker rows per affected token:
    original_tokentype = 'u2f'
    original_active    = '1' or '0'   (so downgrade is lossless)
    deprecated_in      = '3.14'

Revision ID: a1e0ba6ad9dc
Revises: 06b105a4f941
Create Date: 2026-04-15 10:00:00.000000

"""
import logging

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1e0ba6ad9dc'
down_revision = '06b105a4f941'
branch_labels = None
depends_on = None

log = logging.getLogger("alembic.runtime.migration")


def upgrade():
    bind = op.get_bind()

    count = bind.execute(sa.text(
        "SELECT COUNT(*) FROM token WHERE tokentype = 'u2f'"
    )).scalar() or 0

    if count == 0:
        log.info("No u2f tokens found. Nothing to migrate.")
        return

    log.warning(
        "\n" + "=" * 70 + "\n"
        f"Found {count} u2f token(s). U2F is no longer supported as of v3.14.\n"
        "These tokens have been marked as 'deprecated' and disabled, and can\n"
        "no longer be used to authenticate. They are still visible in the\n"
        "token list and can be removed with:\n"
        "    pi-tokenjanitor deprecated delete u2f\n"
        + "=" * 70
    )

    bind.execute(sa.text(
        'INSERT INTO tokeninfo (token_id, "Key", "Value", "Type", "Description") '
        "SELECT id, 'original_tokentype', 'u2f', '', '' "
        "FROM token WHERE tokentype = 'u2f'"
    ))
    bind.execute(sa.text(
        'INSERT INTO tokeninfo (token_id, "Key", "Value", "Type", "Description") '
        "SELECT id, 'original_active', CASE WHEN active THEN '1' ELSE '0' END, '', '' "
        "FROM token WHERE tokentype = 'u2f'"
    ))
    bind.execute(sa.text(
        'INSERT INTO tokeninfo (token_id, "Key", "Value", "Type", "Description") '
        "SELECT id, 'deprecated_in', '3.14', '', '' "
        "FROM token WHERE tokentype = 'u2f'"
    ))

    bind.execute(sa.text(
        "UPDATE token SET tokentype = 'deprecated', active = :inactive "
        "WHERE tokentype = 'u2f'"
    ).bindparams(inactive=False))


def downgrade():
    bind = op.get_bind()

    # Restore active=True for rows whose original_active was '1',
    # and active=False for rows whose original_active was '0'. Two
    # passes instead of a correlated subquery to stay dialect-neutral.
    for stashed, restored in (('1', True), ('0', False)):
        bind.execute(sa.text(
            "UPDATE token SET active = :restored WHERE id IN ("
            '   SELECT token_id FROM tokeninfo '
            '   WHERE "Key" = :active_key AND "Value" = :stashed'
            ") AND id IN ("
            '   SELECT token_id FROM tokeninfo '
            '   WHERE "Key" = :type_key AND "Value" = :type_val'
            ")"
        ).bindparams(
            restored=restored,
            stashed=stashed,
            active_key='original_active',
            type_key='original_tokentype',
            type_val='u2f',
        ))

    # Restore tokentype to u2f
    bind.execute(sa.text(
        "UPDATE token SET tokentype = 'u2f' "
        "WHERE id IN ("
        '   SELECT token_id FROM tokeninfo '
        '   WHERE "Key" = :key AND "Value" = :val'
        ")"
    ).bindparams(key='original_tokentype', val='u2f'))

    # Drop the marker rows — but only those belonging to u2f-origin tokens,
    # not any other deprecation that may also be present.
    bind.execute(sa.text(
        'DELETE FROM tokeninfo '
        'WHERE "Key" IN (:k1, :k2, :k3) AND token_id IN ('
        "   SELECT id FROM token WHERE tokentype = 'u2f'"
        ")"
    ).bindparams(
        k1='original_tokentype',
        k2='original_active',
        k3='deprecated_in',
    ))

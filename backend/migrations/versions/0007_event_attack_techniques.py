"""ATT&CK evidence: the event_attack_techniques table (technique IDs a source explicitly reported for an event).

Additive only: creates one table and its index; no existing table or row is changed. security_events is
created by app.db.init_db, not by a migration, so it must already exist; event_attack_techniques itself may
already exist for the same reason, and is then left as it is.

Only source-supplied evidence is allowed (evidence_kind 'source_supplied'). Inferred or mapped techniques
would need a later migration so that they can never be confused with reported evidence.
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

# At most 32 characters: alembic_version.version_num is VARCHAR(32).
revision: str = "0007_event_attack_techniques"
down_revision: str | None = "0006_add_risk_evaluations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "event_attack_techniques"
INDEX = "ix_event_attack_techniques_technique_id"
UNIQUE = "uq_event_attack_techniques_event_id_technique_id_evidence_kind"
FOREIGN_KEY = "fk_event_attack_techniques_event_id_security_events"

# The structure an existing table must have to be accepted (app.db.init_db creates it from the model).
EXPECTED_COLUMNS = {  # name: (compiled PostgreSQL type, nullable)
    "id": ("UUID", False),
    "event_id": ("UUID", False),
    "technique_id": ("VARCHAR(16)", False),
    "evidence_kind": ("VARCHAR(16)", False),
    "evidence_origin": ("VARCHAR(32)", False),
    "created_at": ("TIMESTAMP WITH TIME ZONE", False),
}
# Each CHECK constraint is verified by behaviour, not text: its stored expression must accept exactly the
# "accept" values and refuse every "refuse" value. PostgreSQL rewrites expressions (casts, IN as = ANY), so
# comparing text would be fragile; evaluating them is exact.
EXPECTED_CHECKS = {
    "ck_event_attack_techniques_technique_id_format": (
        "technique_id",
        ("T1110", "T1110.001", "T0001", "T9999.999"),
        ("T111", "T11100", "t1110", "T1110.01", "T1110.0001", "TA0006", " T1110", "T1110 ", "T1110\n", "T1110.", ""),
    ),
    "ck_event_attack_techniques_evidence_kind_values": (
        "evidence_kind",
        ("source_supplied",),
        ("mapped", "inferred", "Source_Supplied", "source_supplied ", ""),
    ),
    "ck_event_attack_techniques_evidence_origin_values": (
        "evidence_origin",
        ("ingest_field", "collector_field"),
        ("raw_data", "suricata_eve_metadata", "Ingest_Field", "ingest_field ", ""),
    ),
}


def _table_exists(name: str) -> bool:
    return not op.get_context().as_sql and sa.inspect(op.get_bind()).has_table(name)


def _check_problems(bind: sa.Connection, name: str, expression: str) -> list[str]:
    """Evaluate a stored CHECK expression against probe values, read-only (never touches the table).

    The expression may refer only to its own column: any other reference fails to evaluate and is reported.
    """
    column, accepted, refused = EXPECTED_CHECKS[name]
    problems = []
    for value, expected in [*((value, True) for value in accepted), *((value, False) for value in refused)]:
        try:
            with bind.begin_nested():
                result = bind.execute(
                    sa.text(f"SELECT ({expression}) FROM (VALUES (CAST(:value AS varchar))) AS probe({column})"),
                    {"value": value},
                ).scalar()
        except sa.exc.DBAPIError:
            return [f"{name} could not be evaluated against {column} alone"]
        # A CHECK passes when its expression is true or NULL; NULL counts as accepting.
        if (result is not False) != expected:
            problems.append(f"{name} {'refuses' if expected else 'accepts'} {value!r}")
    return problems


def _structure_problems() -> list[str]:
    """Why the existing table does not match this migration (empty when it does). Read-only."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    problems: list[str] = []

    columns = {column["name"]: column for column in inspector.get_columns(TABLE)}
    for name in sorted(set(columns) - set(EXPECTED_COLUMNS)):
        problems.append(f"unexpected column {name}")
    for name, (type_name, nullable) in EXPECTED_COLUMNS.items():
        column = columns.get(name)
        if column is None:
            problems.append(f"missing column {name}")
            continue
        actual_type = column["type"].compile(dialect=bind.dialect)
        if actual_type != type_name or column["nullable"] != nullable:
            problems.append(
                f"column {name} is {actual_type} {'NULL' if column['nullable'] else 'NOT NULL'}, "
                f"expected {type_name} {'NULL' if nullable else 'NOT NULL'}"
            )
        default = column.get("default")
        if name == "created_at":
            if default is None or default.replace(" ", "").lower() not in ("now()", "current_timestamp", "transaction_timestamp()"):
                problems.append(f"column created_at default is {default!r}, expected now()")
        elif default is not None:
            problems.append(f"column {name} has an unexpected default {default!r}")

    primary_key = inspector.get_pk_constraint(TABLE)
    if primary_key.get("constrained_columns") != ["id"]:
        problems.append(f"primary key is on {primary_key.get('constrained_columns')}, expected [id]")

    checks = {check["name"]: check["sqltext"] for check in inspector.get_check_constraints(TABLE)}
    for name in sorted(set(checks) - set(EXPECTED_CHECKS)):
        problems.append(f"unexpected CHECK constraint {name}")
    for name in EXPECTED_CHECKS:
        if name not in checks:
            problems.append(f"missing CHECK constraint {name}")
        else:
            problems.extend(_check_problems(bind, name, checks[name]))

    uniques = {unique["name"]: unique["column_names"] for unique in inspector.get_unique_constraints(TABLE)}
    if uniques.get(UNIQUE) is None:
        problems.append(f"missing unique constraint {UNIQUE}")
    elif sorted(uniques[UNIQUE]) != sorted(["event_id", "technique_id", "evidence_kind"]) or len(uniques[UNIQUE]) != 3:
        problems.append(f"unique constraint {UNIQUE} is on {uniques[UNIQUE]}, expected (event_id, technique_id, evidence_kind)")
    for name in sorted(set(uniques) - {UNIQUE}):
        problems.append(f"unexpected unique constraint {name}")

    foreign_keys = inspector.get_foreign_keys(TABLE)
    expected_fk = [(FOREIGN_KEY, ["event_id"], "security_events", ["id"], "CASCADE")]
    actual_fk = [
        (fk["name"], fk["constrained_columns"], fk["referred_table"], fk["referred_columns"], (fk.get("options", {}).get("ondelete") or "").upper())
        for fk in foreign_keys
    ]
    if actual_fk != expected_fk or any(fk.get("referred_schema") for fk in foreign_keys):
        problems.append(f"foreign keys are {actual_fk}, expected event_id -> security_events(id) ON DELETE CASCADE")

    indexes = [index for index in inspector.get_indexes(TABLE) if not index.get("duplicates_constraint")]
    named = [index for index in indexes if index["name"] == INDEX]
    if not named:
        problems.append(f"missing index {INDEX}")
    else:
        index = named[0]
        if index["column_names"] != ["technique_id"] or index.get("unique") or index.get("dialect_options", {}).get("postgresql_where"):
            problems.append(f"index {INDEX} is not a plain index on exactly (technique_id)")
    for index in indexes:
        if index["name"] != INDEX:
            problems.append(f"unexpected index {index['name']}")
    return problems


def upgrade() -> None:
    if not op.get_context().as_sql and not _table_exists("security_events"):
        raise RuntimeError(
            f"{revision}: the security_events table does not exist (it is created by app.db.init_db), so "
            f"{TABLE} cannot reference it; nothing was changed"
        )
    if _table_exists(TABLE):
        # Accepted only when it is exactly this migration's table (e.g. created by app.db.init_db from the model).
        # Anything else is refused before any DDL; it is never dropped, recreated or repaired automatically.
        problems = _structure_problems()
        if problems:
            raise RuntimeError(
                f"{revision}: {TABLE} already exists but does not match this migration ({'; '.join(problems)}); "
                "nothing was changed"
            )
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("evidence_kind", sa.String(length=16), nullable=False),
        sa.Column("evidence_origin", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "technique_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name=op.f("ck_event_attack_techniques_technique_id_format")
        ),
        sa.CheckConstraint(
            "evidence_kind IN ('source_supplied')", name=op.f("ck_event_attack_techniques_evidence_kind_values")
        ),
        sa.CheckConstraint(
            "evidence_origin IN ('ingest_field', 'collector_field')",
            name=op.f("ck_event_attack_techniques_evidence_origin_values"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["security_events.id"],
            name=op.f("fk_event_attack_techniques_event_id_security_events"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_event_attack_techniques")),
        sa.UniqueConstraint(
            "event_id",
            "technique_id",
            "evidence_kind",
            name=op.f("uq_event_attack_techniques_event_id_technique_id_evidence_kind"),
        ),
    )
    op.create_index(op.f(INDEX), TABLE, ["technique_id"])


def downgrade() -> None:
    # Drops every stored technique ID; security_events and all other tables are untouched.
    op.drop_index(op.f(INDEX), table_name=TABLE)
    op.drop_table(TABLE)

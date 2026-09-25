"""Initial Phase 1 schema — all core tables."""
from alembic import op
import sqlalchemy as sa

revision = "0001_phase1_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hostname", sa.String(255), unique=True, nullable=False),
        sa.Column("ip", sa.String(64), nullable=False, server_default=""),
        sa.Column("os", sa.String(255), nullable=False, server_default=""),
        sa.Column("type", sa.String(64), nullable=False, server_default="workstation"),
        sa.Column("subnet", sa.String(255), nullable=False, server_default=""),
        sa.Column("user", sa.String(255), nullable=False, server_default=""),
        sa.Column("criticality", sa.String(32), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(32), nullable=False, server_default="healthy"),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_seen", sa.DateTime, nullable=False),
    )
    op.create_table("users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("domain", sa.String(255), nullable=False, server_default=""),
        sa.Column("privileged", sa.Integer, nullable=False, server_default="0"),
        sa.Column("disabled", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_table("security_events_metadata",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("source", sa.String(32), nullable=False, server_default="simulator"),
        sa.Column("event_type", sa.String(32), nullable=False, server_default="PROCESS"),
        sa.Column("hostname", sa.String(255), nullable=False, server_default=""),
        sa.Column("user", sa.String(255), nullable=False, server_default=""),
        sa.Column("src_ip", sa.String(64), nullable=False, server_default=""),
        sa.Column("dest_ip", sa.String(64), nullable=False, server_default=""),
        sa.Column("domain", sa.String(255), nullable=False, server_default=""),
        sa.Column("incident_id", sa.String(36), nullable=True),
    )
    op.create_table("iocs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("ioc", sa.String(1024), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("sources", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("reputation", sa.Integer, nullable=True),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("mitre", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("country", sa.String(128), nullable=False, server_default=""),
        sa.Column("asn", sa.String(128), nullable=False, server_default=""),
        sa.Column("first_seen", sa.String(64), nullable=False, server_default=""),
        sa.Column("last_seen", sa.String(64), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="New"),
        sa.UniqueConstraint("ioc", "type", name="uq_ioc_type"),
    )
    op.create_table("threat_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), unique=True, nullable=False),
        sa.Column("last_run", sa.String(64), nullable=False, server_default=""),
        sa.Column("record_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_table("detections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("detector_type", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("severity", sa.String(32), nullable=False, server_default="LOW"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0"),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("reasons", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("evidence", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table("alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("detection_id", sa.String(36), sa.ForeignKey("detections.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="OPEN"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table("incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False, server_default="MEDIUM"),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(32), nullable=False, server_default="NEW"),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("primary_asset_id", sa.String(36), nullable=True),
        sa.Column("assigned_analyst", sa.String(255), nullable=False, server_default=""),
        sa.Column("summary", sa.Text, nullable=False, server_default=""),
        sa.Column("risk_explanation", sa.Text, nullable=False, server_default=""),
    )
    for tbl, col in [("incident_events", "event_id"), ("incident_iocs", "ioc_id"), ("incident_assets", "asset_id"), ("incident_users", "user_id")]:
        fk_table = {"event_id": None, "ioc_id": "iocs.id", "asset_id": "assets.id", "user_id": "users.id"}[col]
        cols = [sa.Column("id", sa.String(36), primary_key=True), sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id"), nullable=False)]
        cols.append(sa.Column(col, sa.String(36), sa.ForeignKey(fk_table) if fk_table else None, nullable=False))
        op.create_table(tbl, *cols)
    op.create_table("mitre_techniques",
        sa.Column("technique_id", sa.String(32), primary_key=True),
        sa.Column("tactic", sa.String(128), nullable=False, server_default=""),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("subtechnique", sa.String(255), nullable=False, server_default=""),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
    )
    op.create_table("detection_mitre",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("detection_id", sa.String(36), sa.ForeignKey("detections.id"), nullable=False),
        sa.Column("technique_id", sa.String(32), sa.ForeignKey("mitre_techniques.technique_id"), nullable=False),
    )
    op.create_table("investigations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("summary", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table("investigation_notes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("author", sa.String(255), nullable=False, server_default=""),
        sa.Column("note", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table("response_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="SIMULATION"),
        sa.Column("status", sa.String(32), nullable=False, server_default="REQUESTED"),
        sa.Column("actor", sa.String(255), nullable=False, server_default=""),
        sa.Column("target", sa.String(512), nullable=False, server_default=""),
        sa.Column("result", sa.String(255), nullable=False, server_default=""),
        sa.Column("metadata", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table("audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("actor", sa.String(255), nullable=False, server_default=""),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("target", sa.String(512), nullable=False, server_default=""),
        sa.Column("incident_id", sa.String(36), nullable=True),
        sa.Column("result", sa.String(255), nullable=False, server_default=""),
        sa.Column("metadata", sa.JSON, nullable=False, server_default="{}"),
    )
    op.create_table("rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(128), unique=True, nullable=False),
        sa.Column("version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.Column("enabled", sa.Integer, nullable=False, server_default="1"),
        sa.Column("severity", sa.String(32), nullable=False, server_default="MEDIUM"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("mitre", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
    )
    op.create_table("model_metadata",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("trained_at", sa.String(64), nullable=False, server_default=""),
        sa.Column("sample_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("thresholds", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("loaded_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    for tbl in ["model_metadata", "rules", "audit_logs", "response_actions", "investigation_notes", "investigations", "detection_mitre", "mitre_techniques", "incident_users", "incident_assets", "incident_iocs", "incident_events", "incidents", "alerts", "detections", "threat_sources", "iocs", "security_events_metadata", "users", "assets"]:
        op.drop_table(tbl)

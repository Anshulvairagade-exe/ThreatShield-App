"""Phase: reversible response — ioc_blocks table for BLOCK/UNBLOCK state."""
from alembic import op
import sqlalchemy as sa

revision = "0002_ioc_blocks"
down_revision = "0001_phase1_init"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("ioc_blocks",
        sa.Column("ioc", sa.String(1024), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="BLOCKED"),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ioc_blocks")

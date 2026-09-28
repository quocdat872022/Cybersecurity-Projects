"""
©AngelaMos | 2026
add training_state

Revision ID: a3f7c9e2d514
Revises: 65c8ac60f6f6
Create Date: 2026-02-12 09:14:02.881204
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

revision: str = "a3f7c9e2d514"
down_revision: Union[str, None] = "65c8ac60f6f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "training_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("labels_since_last_train", sa.Integer(), nullable=False),
        sa.Column("last_retrain_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("training_state")
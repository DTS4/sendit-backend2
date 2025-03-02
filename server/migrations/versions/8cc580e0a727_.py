"""empty message

Revision ID: 8cc580e0a727
Revises: 2c9d65abe0c7
Create Date: 2025-03-02 19:33:24.489965

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '8cc580e0a727'
down_revision = '2c9d65abe0c7'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add the `distance` column as NULLABLE
    with op.batch_alter_table('parcels', schema=None) as batch_op:
        batch_op.add_column(sa.Column('distance', sa.Float(), nullable=True))

    # Step 2: Update existing rows to set a default value for `distance`
    op.execute("UPDATE parcels SET distance = 0 WHERE distance IS NULL")

    # Step 3: Alter the column to enforce NOT NULL
    with op.batch_alter_table('parcels', schema=None) as batch_op:
        batch_op.alter_column('distance', nullable=False)

    # Step 4: Drop the unused columns
    with op.batch_alter_table('parcels', schema=None) as batch_op:
        batch_op.drop_column('cancel_reason')
        batch_op.drop_column('refund_status')
        batch_op.drop_column('cancel_date')


def downgrade():
    # Recreate the dropped columns
    with op.batch_alter_table('parcels', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cancel_date', postgresql.TIMESTAMP(), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('refund_status', sa.VARCHAR(length=50), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('cancel_reason', sa.VARCHAR(length=200), autoincrement=False, nullable=True))

    # Drop the `distance` column
    with op.batch_alter_table('parcels', schema=None) as batch_op:
        batch_op.drop_column('distance')
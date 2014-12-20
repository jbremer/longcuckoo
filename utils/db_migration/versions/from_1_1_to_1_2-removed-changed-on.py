# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""removed changed-on columns

Revision ID: 5adbab2b7915
Revises: 18eee46c6f81
Create Date: 2014-12-20 08:16:26.544725

"""

# revision identifiers, used by Alembic.
revision = '5adbab2b7915'
down_revision = '18eee46c6f81'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade():
    op.drop_column('machines', 'locked_changed_on')
    op.drop_column('machines', 'status_changed_on')


def downgrade():
    # postgresql.TIMESTAMP() is probably not generic enough..
    op.add_column('machines', sa.Column('status_changed_on', postgresql.TIMESTAMP(), autoincrement=False, nullable=True))
    op.add_column('machines', sa.Column('locked_changed_on', postgresql.TIMESTAMP(), autoincrement=False, nullable=True))

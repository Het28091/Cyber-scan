"""Reject future state schemas before any legacy CREATE/UPDATE operation."""
from .security import PolicyError


def guard_schema(connection):
    version=connection.execute('PRAGMA user_version').fetchone()[0]
    if version>1:
        connection.close()
        raise PolicyError('database schema is newer than this application; use its matching application version')

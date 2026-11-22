"""Importing this package registers every check module.

To add a new group: create a module here and import it below.
"""

from hardaudit.checks import accounts, ssh  # noqa: F401

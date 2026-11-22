"""Importing this package registers every check module.

To add a new group: create a module here and import it below. The import
order is the order of the report, so automatic sorting is turned off.
"""

# isort: off
from hardaudit.checks import (  # noqa: F401
    ssh,
    accounts,
    permissions,
    network,
    logs,
    passwords,
)
# isort: on

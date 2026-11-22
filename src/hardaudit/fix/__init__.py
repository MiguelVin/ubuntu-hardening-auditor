"""Automatic remediation (--fix).

Design rule: only fix what is safe to change without a human decision.
Deleting an account, editing sudoers, enabling a firewall or stopping a
service can lock people out or break production, so those stay manual.
"""

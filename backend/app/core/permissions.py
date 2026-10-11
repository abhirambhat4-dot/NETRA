"""Roles and the controlled-response permissions they grant.

Roles are stored as plain strings in ``users.role``. Registration always assigns ``operator``;
``approver`` and ``admin`` are never self-assigned and are granted only by changing the stored role.
A role that is not listed here grants no permissions.
"""

from enum import StrEnum


class Role(StrEnum):
    OPERATOR = "operator"
    APPROVER = "approver"
    ADMIN = "admin"


class Permission(StrEnum):
    REQUEST_AUTHORIZATION = "request_authorization"
    # Approve or reject a pending authorization request.
    RESOLVE_AUTHORIZATION = "resolve_authorization"
    # Execute an approved containment and verify its result.
    EXECUTE_CONTAINMENT = "execute_containment"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    Role.OPERATOR: frozenset({Permission.REQUEST_AUTHORIZATION, Permission.EXECUTE_CONTAINMENT}),
    Role.APPROVER: frozenset(Permission),
    Role.ADMIN: frozenset(Permission),
}


def has_permission(role: str | None, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role or "", frozenset())

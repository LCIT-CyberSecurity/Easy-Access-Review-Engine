"""Small, explicit capability map for the supported source connectors."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectorCapabilities:
    attribute_mapping: bool
    safe_attribute_sampling: bool
    source_browser: bool
    native_permissions: bool
    native_targets: bool


_DIRECTORY_CAPABILITIES = ConnectorCapabilities(
    attribute_mapping=True,
    safe_attribute_sampling=True,
    source_browser=True,
    native_permissions=False,
    native_targets=False,
)

_CAPABILITIES = {
    "active_directory": _DIRECTORY_CAPABILITIES,
    "openldap": _DIRECTORY_CAPABILITIES,
}
_UNSUPPORTED = ConnectorCapabilities(False, False, False, False, False)


def connector_capabilities(connector_type: str) -> ConnectorCapabilities:
    """Return declared support without imposing a connector implementation framework."""
    return _CAPABILITIES.get(connector_type, _UNSUPPORTED)

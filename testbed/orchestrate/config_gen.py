"""Re-export of the tunnel configuration model, which now lives in the product.

It used to live here, and the product imported it from the testbed. That made
``sentinel remediate`` and ``sentinel watch`` fail in every installed copy, because
``testbed/`` is not part of the distribution — see
:mod:`ipsec_sentinel.remediate.config`.

This shim keeps the harness's imports working. New code should import from the product.
"""

from __future__ import annotations

from ipsec_sentinel.remediate.config import (
    AEAD_ENCRYPTIONS,
    DEFAULT_TOPOLOGY_V4,
    DEFAULT_TOPOLOGY_V6,
    IKEVersion,
    IPVersion,
    Mode,
    Role,
    Topology,
    TunnelConfig,
    default_topology,
    is_aead,
    render_swanctl_conf,
)

__all__ = [
    "AEAD_ENCRYPTIONS",
    "DEFAULT_TOPOLOGY_V4",
    "DEFAULT_TOPOLOGY_V6",
    "IKEVersion",
    "IPVersion",
    "Mode",
    "Role",
    "Topology",
    "TunnelConfig",
    "default_topology",
    "is_aead",
    "render_swanctl_conf",
]

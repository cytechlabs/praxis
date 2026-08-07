"""Shared SSRF guard + no-redirect delivery for outbound HTTP targets.

Used by the two places Praxis makes operator-configured outbound HTTP requests
from inside the trust boundary: alert webhooks and audit HTTP sinks. Both are
attractive SSRF vectors, so this module is the single choke point that:

* accepts only ``http(s)`` URLs with a host;
* resolves the host's DNS and FAILS CLOSED if any resolved address is a
  loopback / private (RFC1918 / ULA) / link-local / multicast / reserved /
  unspecified / cloud-metadata address (IPv4 and IPv6, including IPv4-mapped
  IPv6). A mixed answer set (one allowed + one disallowed) is rejected;
* pins delivery to a validated IP while preserving the TLS SNI / certificate
  hostname and the ``Host`` header, so a name that passes validation cannot be
  DNS-rebound to a disallowed address between check and connect;
* disables redirects, so a target cannot 3xx-bounce the request to an internal
  address.

Internal targets are blocked by default. Each caller owns its own explicit,
independent escape hatch so one path's override can never silently open the
other's:

* audit HTTP sinks: ``AUDIT_SINK_ALLOW_PRIVATE_TARGETS`` (kept from the prior
  audit-sink policy for backwards compatibility);
* alert webhooks: ``ALERT_ALLOW_PRIVATE_TARGETS``;
* OIDC discovery / token / JWKS: ``OIDC_ALLOW_PRIVATE_TARGETS`` (for an
  on-network IdP such as a self-hosted Keycloak).

``validate_target`` / ``post`` / ``get_async`` / ``post_async`` never read env
implicitly; callers pass the resolved ``allow_private`` for their own scope via
the helpers below.

Both a synchronous (``post``) and asynchronous (``get_async`` / ``post_async``)
delivery path exist; all three share the same validate-then-pin core so the SSRF
guarantees are identical regardless of transport.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Dict, Optional, Union
from urllib.parse import urlparse, urlunparse

import httpx

# Per-scope escape-hatch env flags. They are deliberately independent so one
# scope's override cannot silently open another's.
_AUDIT_ALLOW_PRIVATE_ENV = "AUDIT_SINK_ALLOW_PRIVATE_TARGETS"
_ALERT_ALLOW_PRIVATE_ENV = "ALERT_ALLOW_PRIVATE_TARGETS"
_OIDC_ALLOW_PRIVATE_ENV = "OIDC_ALLOW_PRIVATE_TARGETS"

# Well-known cloud metadata / local names that must be blocked before DNS even
# when a resolver would (mis)map them.
_LOCAL_NAMES = {"localhost", "metadata", "metadata.google.internal"}

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class SsrfBlocked(ValueError):
    """Raised when an outbound HTTP target is not allowed."""


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes")


def allow_private_targets() -> bool:
    """Audit-sink escape hatch (``AUDIT_SINK_ALLOW_PRIVATE_TARGETS``).

    Kept for backwards compatibility with the prior audit-sink policy. Callers
    pass the result to ``validate_target`` / ``post`` explicitly; the guard never
    reads it implicitly, so this override applies to audit sinks only."""
    return _env_flag(_AUDIT_ALLOW_PRIVATE_ENV)


def alert_allow_private_targets() -> bool:
    """Alert-webhook escape hatch (``ALERT_ALLOW_PRIVATE_TARGETS``).

    Independent of the audit knob so enabling internal audit sinks does not open
    alert webhook destinations. Off by default — alerts block internal targets
    unless an operator sets this explicitly."""
    return _env_flag(_ALERT_ALLOW_PRIVATE_ENV)


def oidc_allow_private_targets() -> bool:
    """OIDC escape hatch (``OIDC_ALLOW_PRIVATE_TARGETS``).

    Independent of the audit/alert knobs. Off by default: OIDC discovery, token,
    and JWKS requests block internal targets unless an operator explicitly opts in
    to reach an on-network IdP (e.g. a self-hosted Keycloak)."""
    return _env_flag(_OIDC_ALLOW_PRIVATE_ENV)


def _normalize(ip: _IPAddress) -> _IPAddress:
    """Collapse an IPv4-mapped IPv6 address to its IPv4 form so it classifies
    correctly (``::ffff:127.0.0.1`` must be treated as loopback)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def ip_is_blocked(ip: _IPAddress) -> bool:
    """True when *ip* is one of the address classes an outbound request must not
    reach by default."""
    ip = _normalize(ip)
    return bool(
        ip.is_loopback
        or ip.is_private  # RFC1918 + IPv6 ULA (fc00::/7)
        or ip.is_link_local  # 169.254.0.0/16 + fe80::/10 (incl. cloud metadata)
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve(host: str) -> list[_IPAddress]:
    """All addresses *host* resolves to. A literal IP resolves to itself.

    Raises ``SsrfBlocked`` if the name cannot be resolved (fail closed rather
    than allowing an unresolvable target through)."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    # Local import so tests can monkeypatch ``socket.getaddrinfo`` at the module
    # they expect; import here keeps the dependency explicit.
    import socket

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SsrfBlocked(f"could not resolve host {host!r}") from exc
    ips: list[_IPAddress] = []
    for info in infos:
        sockaddr = info[4]
        try:
            ips.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not ips:
        raise SsrfBlocked(f"no usable address for host {host!r}")
    return ips


def validate_target(
    url: str,
    *,
    allow_private: Optional[bool] = None,
    require_https: bool = False,
) -> _IPAddress:
    """Validate an outbound target URL and return a validated IP to pin to.

    * ``allow_private`` (defaults to ``False`` — blocked) skips the
      disallowed-address checks for an operator-approved internal collector. The
      guard never reads an env flag itself; callers pass their own scope's
      resolved override (see ``allow_private_targets`` /
      ``alert_allow_private_targets``) so the two paths cannot inherit each
      other's escape hatch.
    * ``require_https`` enforces the audit-sink policy that non-local targets
      must use TLS.

    Raises ``SsrfBlocked`` on any disallowed target.
    """
    if allow_private is None:
        allow_private = False

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SsrfBlocked("target must be an http:// or https:// URL")
    host = parsed.hostname
    if not host:
        raise SsrfBlocked("target must include a host")

    name = host.lower().rstrip(".")
    is_local_name = (
        name in _LOCAL_NAMES
        or name.endswith(".localhost")
        or name.endswith(".internal")
    )

    resolved = _resolve(host)
    disallowed = [ip for ip in resolved if ip_is_blocked(ip)]
    internal = bool(disallowed) or is_local_name

    if internal and not allow_private:
        if is_local_name:
            raise SsrfBlocked(f"target host {host!r} is a local/metadata name")
        raise SsrfBlocked(
            f"target {host!r} resolves to a disallowed address ({disallowed[0]})"
        )

    if require_https and parsed.scheme == "http" and not internal:
        raise SsrfBlocked("target must use https for non-local hosts")

    # Pin to a validated address. When the whole set is allowed, any is safe;
    # when internal targets are explicitly allowed, prefer the first resolved.
    return resolved[0]


def _build_pinned_request(
    url: str,
    headers: Optional[Dict[str, str]],
    *,
    allow_private: Optional[bool],
    require_https: bool,
) -> tuple:
    """Validate *url* (at delivery time) and return the pieces needed to send a
    pinned, DNS-rebind-safe request: ``(pinned_url, send_headers, sni_host)``.

    ``pinned_url`` has the host replaced by the validated literal IP, so the
    socket connects to that exact address; ``send_headers`` carries the original
    ``Host`` authority; ``sni_host`` keeps TLS SNI + certificate verification
    bound to the real hostname. Raises ``SsrfBlocked`` on a disallowed target.
    Shared by the sync and async delivery paths so their guarantees are identical.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ip = validate_target(url, allow_private=allow_private, require_https=require_https)

    port_suffix = f":{parsed.port}" if parsed.port else ""
    host_authority = f"{host}{port_suffix}"
    ip_text = f"[{ip}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)
    pinned_url = urlunparse(
        (
            parsed.scheme,
            f"{ip_text}{port_suffix}",
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    send_headers = dict(headers or {})
    # Route by the real hostname even though we connect to the pinned IP.
    send_headers["Host"] = host_authority
    return pinned_url, send_headers, host


def validate_url_shape(
    url: str,
    *,
    allow_private: Optional[bool] = None,
    require_https: bool = False,
) -> None:
    """Validate an outbound URL's scheme/host WITHOUT resolving DNS.

    For a URL the backend hands off but does NOT itself fetch: the OIDC
    ``authorization_endpoint`` the browser navigates to. Enforces an
    ``http(s)`` scheme (blocking ``javascript:``/``file:`` and, when
    ``require_https``, plain ``http`` for non-local hosts), requires a host, and
    rejects a host given as a disallowed literal IP or a local/metadata name.
    Names are NOT resolved here (the party that actually connects, the browser,
    does that); backend-fetched endpoints use ``validate_target`` for the full
    DNS-resolved + pinned check. Raises ``SsrfBlocked`` on a disallowed target.
    """
    if allow_private is None:
        allow_private = False

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SsrfBlocked("target must be an http:// or https:// URL")
    host = parsed.hostname
    if not host:
        raise SsrfBlocked("target must include a host")

    name = host.lower().rstrip(".")
    is_local_name = (
        name in _LOCAL_NAMES
        or name.endswith(".localhost")
        or name.endswith(".internal")
    )
    literal_blocked = False
    try:
        literal_blocked = ip_is_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass  # a hostname, not a literal IP; the browser resolves it

    internal = literal_blocked or is_local_name
    if internal and not allow_private:
        raise SsrfBlocked(f"target {host!r} is a disallowed address or name")
    if require_https and parsed.scheme == "http" and not internal:
        raise SsrfBlocked("target must use https for non-local hosts")


def post(
    url: str,
    *,
    content: bytes,
    headers: Dict[str, str],
    timeout: float,
    allow_private: Optional[bool] = None,
    require_https: bool = False,
) -> httpx.Response:
    """Validate *url* (at delivery time) and POST *content* to the validated,
    pinned IP with redirects disabled.

    The request connects to the validated IP address directly, so the target
    cannot be DNS-rebound between validation and connect, while the ``Host``
    header and TLS SNI / certificate verification still use the original
    hostname. Raises ``SsrfBlocked`` if the target is disallowed; httpx errors
    propagate to the caller.
    """
    pinned_url, send_headers, sni_host = _build_pinned_request(
        url, headers, allow_private=allow_private, require_https=require_https
    )
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        # ``sni_hostname`` keeps TLS SNI + certificate verification bound to the
        # real hostname while the socket connects to the pinned IP.
        return client.post(
            pinned_url,
            content=content,
            headers=send_headers,
            extensions={"sni_hostname": sni_host},
        )


async def get_async(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float,
    allow_private: Optional[bool] = None,
    require_https: bool = True,
) -> httpx.Response:
    """Async GET of a validated, pinned target with redirects disabled.

    The async counterpart of ``post`` for read-style outbound calls (OIDC
    discovery + JWKS). Same validate-then-pin core: connects to the validated
    literal IP, preserves the ``Host`` header and TLS SNI / cert hostname, and
    never follows redirects. ``require_https`` defaults to ``True``: these
    outbound calls should use TLS unless an explicitly-allowed internal target
    opts out. Raises ``SsrfBlocked`` on a disallowed target.
    """
    pinned_url, send_headers, sni_host = _build_pinned_request(
        url, headers, allow_private=allow_private, require_https=require_https
    )
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return await client.get(
            pinned_url,
            headers=send_headers,
            extensions={"sni_hostname": sni_host},
        )


async def post_async(
    url: str,
    *,
    content: bytes,
    headers: Optional[Dict[str, str]] = None,
    timeout: float,
    allow_private: Optional[bool] = None,
    require_https: bool = True,
) -> httpx.Response:
    """Async POST of *content* to a validated, pinned target with redirects
    disabled. The async counterpart of ``post`` for the OIDC token exchange.
    ``require_https`` defaults to ``True``. Raises ``SsrfBlocked`` on a disallowed
    target.
    """
    pinned_url, send_headers, sni_host = _build_pinned_request(
        url, headers, allow_private=allow_private, require_https=require_https
    )
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return await client.post(
            pinned_url,
            content=content,
            headers=send_headers,
            extensions={"sni_hostname": sni_host},
        )

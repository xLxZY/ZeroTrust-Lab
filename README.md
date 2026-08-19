# Zero Trust Architecture Inspired Lab

A hands-on **Zero Trust Architecture (ZTA)** lab distributed across **2 physical machines, 8 virtual machines, and 4 segmented VLANs**.

## Architecture Overview

The lab implements three independent enforcement layers. A request must successfully pass **all three** before access is granted:

* **Cloudflare Edge** - identity allowlist, geographic restrictions, WARP device posture, and a custom WAF rule blocking offensive-tool User-Agents.
* **Traefik (PEP)** - `forwardAuth` middleware is enforced on every route; nothing is proxied without an authentication check.
* **Authelia** - TOTP authentication per session, `default_policy: deny`, 30-minute inactivity timeout, and 3-attempt account lockout.

No single control is trusted in isolation. Access requires independent validation across the **edge, proxy, and identity layers**.

## Network Segmentation

Four trust zones are enforced by **pfSense** using a default-deny policy:

| VLAN    | Trust Zone | Purpose                                        |
| ------- | ---------- | ---------------------------------------------- |
| VLAN 10 | MGMT       | Splunk SIEM and restricted management services |
| VLAN 20 | SERVICES   | Zero Trust proxy layer                         |
| VLAN 30 | USERS      | Workstations and application servers           |
| VLAN 40 | ISOLATED   | Completely isolated from MGMT and SERVICES     |

> **VLAN segmentation alone is not Zero Trust.** It is one layer within a broader multi-layer security model.

Validation included policy-enforcement tests, segmented-access verification, and unauthorized-route blocking across the trust zones.

## Telemetry Pipeline

The lab also includes a security telemetry pipeline:

**rsyslog → Vector → Splunk**

Vector performs VRL-based normalization and filtering before forwarding events to Splunk. This reduced log volume by approximately **85%** while preserving security-relevant events.

## Real Engineering Problems

The most valuable lessons came from the problems that don't usually appear in tutorials:

* Silent `rsyslog` failures with no diagnostic output
* Vector VRL syntax constraints that werenot clearly documented
* Suricata resetting its syslog destination 
* Traefik's Docker provider silently dropping routes after restarts

These issues required troubleshooting the actual system rather than following a predefined tutorial.

## Key Takeaway

**Zero Trust is not a product.**

No single vendor delivers Zero Trust by itself. It is a design commitment that has to be applied across every layer:

**Edge → Proxy → Identity → Network → Monitoring**

Remove one layer, and the attack surface expands.

## Documentation

The full write-up includes:

* Architecture diagrams
* Telemetry pipeline design
* NIST SP 800-207 mapping
* Implementation details
* Validation and testing
* Troubleshooting notes and lessons learned

**Full write-up:**
https://kar1m.site/blog#zero-trust-lab-build

# Zero Trust Architecture inspired lab- distributed across 2 physical machines, 8 VMs, and 4 segmented VLANs.

The Access Control Model

Three independent enforcement layers -  a request must pass all three before access is granted:

→ Cloudflare Edge: identity allowlist + geographic restriction + device posture (WARP) + custom WAF blocking offensive tool User-Agents
→ Traefik (PEP): forwardAuth middleware on every route - nothing gets proxied without an auth check
→ Authelia: TOTP per session, default_policy: deny, 30-min inactivity timeout, 3-attempt  lockout

No single control is trusted in isolation; access requires independent validation across edge, proxy, and identity layers.

 Network Segmentation

4 trust zones enforced by pfSense with a default-deny policy:
- VLAN 10 (MGMT) - Splunk SIEM, restricted
- VLAN 20 (SERVICES) - ZTA proxy layer
- VLAN 30 (USERS) - workstations and app servers
- VLAN 40 (ISOLATED) - completely cut off from MGMT and SERVICES

VLAN segmentation alone isn't Zero Trust. It's one layer of a multi-layer model.

Validation included policy enforcement tests, segmented access verification, and unauthorized route blocking across all trust zones.

 Telemetry Pipeline

Built a telemetry pipeline (rsyslog → Vector → Splunk) with VRL normalization and filtering, reducing log volume ~85% while preserving security-relevant events.

 Real Engineering, Real Problems

The challenges I hit were the most valuable part - silent rsyslog failures with no diagnostic output, Vector VRL syntax constraints that aren't in the docs, Suricata resetting its syslog destination after every pfSense update, Traefik's Docker provider silently dropping routes after restarts.

None of that shows up in tutorials. It shows up in production.

 The Takeaway

Zero Trust is not a product. No vendor delivers it. It's a design commitment across every layer simultaneously - edge, proxy, identity, network, and monitoring. Remove a layer and the attack surface expands immediately.

Full write-up with architecture diagrams, pipeline design, NIST SP 800-207 mapping, and engineering notes:

https://kar1m.site/blog#zero-trust-lab-build

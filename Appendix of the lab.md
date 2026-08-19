# Zero Trust Lab  - Technical Appendix
## Everything in this 1 file instead of multiple files that will make you feel lost 
## all secrets are random and UNUSED  IDC about them 

## Note if  it worked on mine it doesnt have to works on yours :)
**Author:** Karim (LxZy)



D1 = Decvice1 /
D2 = Device 2 

---

## 1. Infrastructure Overview

| Component | Role | IP | VLAN | Device |
|---|---|---|---|---|
| splunk-vm | SIEM - Splunk 9.3.2 - Vector D1 | 192.168.10.20 | VLAN10 - MGMT | D1 |
| services-vm | Traefik - Authelia - cloudflared | 192.168.20.10 | VLAN20 - SERVICES | D1 |
| pfSense-D1 | Firewall - IPsec - Suricata | 192.168.10.1 / 192.168.20.1 | Perimeter D1 | D1 |
| appserver-vm | DVWA attack target - auditd | 192.168.30.50 | VLAN30 - USERS | D2 |
| user-vm-1 | Simulated workstation - bob - svc_backup | 192.168.30.10 | VLAN30 - USERS | D2 |
| user-vm-2 | Simulated workstation - carol | 192.168.30.20 | VLAN30 - USERS | D2 |
| collectorvm | Vector D2 log aggregator | 192.168.30.100 | VLAN30 - USERS | D2 |
| pfSense-D2 | Firewall - IPsec - Suricata | 192.168.30.1 / 192.168.40.1 | Perimeter D2 | D2 |
| kali-vm | Attack simulation - isolated | 192.168.40.10 | VLAN40 - ATTACK | D2 |

---

## 2. File Inventory

---

### File: vector.toml (D2)

**Path:** `/etc/vector/vector.toml`
**Host:** collectorvm (192.168.30.100)
**Purpose:** Central D2 log aggregation pipeline. Receives syslog from all D2 VMs, pfSense-D2 firewall logs, and Suricata-D2 EVE JSON. Filters noise, parses and enriches events, forwards to Splunk HEC over IPsec tunnel.

**Related Components:** Splunk, pfSense-D2, Suricata-D2, appserver-vm, user-vm-1, user-vm-2

**Configuration:**

```toml
[sources.d2_vms]
  type    = "syslog"
  address = "0.0.0.0:514"
  mode    = "udp"

[sources.pfsense]
  type    = "syslog"
  address = "0.0.0.0:515"
  mode    = "udp"

[sources.suricata]
  type    = "syslog"
  address = "0.0.0.0:516"
  mode    = "udp"

[transforms.vm_filter]
  type   = "filter"
  inputs = ["d2_vms"]
  condition.type   = "vrl"
  condition.source = '''
    appname = string(.appname) ?? ""
    msg     = string(.message) ?? ""
    !(appname == "CRON" || contains(msg, "apt") || contains(msg, "dpkg") || contains(msg, "systemd-timesyncd") || contains(msg, "NetworkManager") || contains(msg, "snapd"))
  '''

[transforms.vm_enrich]
  type   = "remap"
  inputs = ["vm_filter"]
  source = '''
    .source_site = "device2"
    .lab_zone    = "users"
    .log_type    = "system"
    appname = string(.appname) ?? ""
    msg     = string(.message) ?? ""
    if appname == "sshd" {
      .log_type = "auth"
      if contains(msg, "Failed password")   { .auth_event = "ssh_fail" }
      if contains(msg, "Accepted password") { .auth_event = "ssh_success" }
      if contains(msg, "Invalid user")      { .auth_event = "ssh_invalid" }
      parsed, err = parse_regex(msg, r'(?:Failed|Accepted) (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
      if err == null { .ssh = parsed }
    }
    if appname == "sudo" {
      .log_type   = "privilege"
      .auth_event = "sudo"
      parsed, err = parse_regex(msg, r'(?P<user>\S+) : TTY=\S+ ; USER=(?P<run_as>\S+) ; COMMAND=(?P<cmd>.+)')
      if err == null { .sudo = parsed }
    }
    if appname == "audispd" || appname == "auditd" {
      .log_type = "audit"
      if contains(msg, "execve")    { .audit_event = "cmd_exec" }
      if contains(msg, "connect")   { .audit_event = "net_connect" }
      if contains(msg, "USER_AUTH") { .audit_event = "auth" }
    }
  '''

[transforms.pfsense_enrich]
  type   = "remap"
  inputs = ["pfsense"]
  source = '''
    .source_site = "device2"
    .host_vm     = "pfsense-d2"
    .lab_zone    = "perimeter"
    .log_type    = "firewall"
    if contains(string(.message) ?? "", "filterlog") {
      parts = split(string(.message) ?? "", ",")
      if length(parts) >= 9 {
        .firewall = {"action":parts[6],"direction":parts[7],"ip_version":parts[8]}
        if parts[8] == "4" && length(parts) >= 20 {
          .firewall.src_ip = parts[18]
          .firewall.dst_ip = parts[19]
          .firewall.protocol = parts[16]
        }
      }
    }
  '''

[transforms.suricata_parse]
  type   = "remap"
  inputs = ["suricata"]
  source = '''
    .source_site = "device2"
    .host_vm     = "pfsense-d2"
    .lab_zone    = "perimeter"
    .log_type    = "ids_alert"
    eve, err = parse_json(string(.message) ?? "")
    if err == null {
      .event_type     = string(eve.event_type) ?? ""
      .src_ip         = string(eve.src_ip) ?? ""
      .dst_ip         = string(eve.dest_ip) ?? ""
      .proto          = string(eve.proto) ?? ""
      if exists(eve.alert) {
        .alert_sig      = string(eve.alert.signature) ?? ""
        .alert_severity = eve.alert.severity
        .alert_category = string(eve.alert.category) ?? ""
      }
    }
  '''

[sinks.splunk_vmlogs]
  type       = "splunk_hec_logs"
  inputs     = ["vm_enrich"]
  endpoint   = "http://192.168.10.20:8088"
  token      = "f4b0c50d-d856-4f00-9fa2-51e8ace1a960"
  index      = "main"
  source     = "d2-vms"
  sourcetype = "syslog"
  [sinks.splunk_vmlogs.encoding]
    codec = "json"

[sinks.splunk_pfsense]
  type       = "splunk_hec_logs"
  inputs     = ["pfsense_enrich"]
  endpoint   = "http://192.168.10.20:8088"
  token      = "f4b0c50d-d856-4f00-9fa2-51e8ace1a960"
  index      = "main"
  source     = "pfsense-d2"
  sourcetype = "pfsense_filterlog"
  [sinks.splunk_pfsense.encoding]
    codec = "json"

[sinks.splunk_suricata]
  type       = "splunk_hec_logs"
  inputs     = ["suricata_parse"]
  endpoint   = "http://192.168.10.20:8088"
  token      = "f4b0c50d-d856-4f00-9fa2-51e8ace1a960"
  index      = "main"
  source     = "suricata-d2"
  sourcetype = "suricata"
  [sinks.splunk_suricata.encoding]
    codec = "json"
```

**Notes:**
- UDP 514 receives D2 VM syslog (appserver, user-vm-1, user-vm-2)
- UDP 515 receives pfSense-D2 filterlog
- UDP 516 receives Suricata-D2 EVE JSON
- VRL noise filter removes ~85% of volume before enrichment
- All events tagged with source_site and lab_zone for cross-site Splunk correlation

---

### File: vector.toml (D1)

**Path:** `/etc/vector/vector.toml`
**Host:** splunk-vm (192.168.10.20)
**Purpose:** D1 log aggregation pipeline. Collects local journald events, services-vm syslog, pfSense-D1 firewall logs, and Suricata-D1 EVE JSON. Delivers to Splunk HEC on localhost.

**Related Components:** Splunk, pfSense-D1, Suricata-D1, services-vm

**Configuration:**

```toml
[sources.d1_local]
  type              = "journald"
  current_boot_only = true

[sources.services_vm]
  type    = "syslog"
  address = "0.0.0.0:514"
  mode    = "udp"

[sources.pfsense_d1]
  type    = "syslog"
  address = "0.0.0.0:515"
  mode    = "udp"

[sources.suricata_d1]
  type    = "syslog"
  address = "0.0.0.0:516"
  mode    = "udp"

[transforms.d1_local_filter]
  type   = "filter"
  inputs = ["d1_local"]
  condition.type   = "vrl"
  condition.source = '''
    unit = string(.SYSTEMD_UNIT) ?? ""
    msg  = string(.MESSAGE) ?? ""
    !(unit == "cron.service" || contains(msg, "apt") || contains(msg, "dpkg") || contains(msg, "systemd-timesyncd") || contains(msg, "NetworkManager") || contains(msg, "snapd") || contains(msg, "Started Session"))
  '''

[transforms.d1_local_enrich]
  type   = "remap"
  inputs = ["d1_local_filter"]
  source = '''
    .source_site = "device1"
    .host_vm     = "splunk-vm"
    .lab_zone    = "mgmt"
    .log_type    = "system"
    .message     = string(.MESSAGE) ?? ""
  '''

[transforms.services_filter]
  type   = "filter"
  inputs = ["services_vm"]
  condition.type   = "vrl"
  condition.source = '''
    msg = string(.message) ?? ""
    !(contains(msg, "apt") || contains(msg, "dpkg") || contains(msg, "systemd-timesyncd") || contains(msg, "snapd") || contains(msg, "CRON"))
  '''

[transforms.services_enrich]
  type   = "remap"
  inputs = ["services_filter"]
  source = '''
    .source_site = "device1"
    .host_vm     = "services-vm"
    .lab_zone    = "services"
    .log_type    = "system"
    msg = string(.message) ?? ""
    if contains(msg, "traefik")                                          { .service = "traefik"     .log_type = "proxy" }
    if contains(msg, "authelia") || contains(msg, "Authelia")            { .service = "authelia"    .log_type = "auth" }
    if contains(msg, "cloudflared")                                      { .service = "cloudflared" .log_type = "tunnel" }
  '''

[transforms.pfsense_d1_enrich]
  type   = "remap"
  inputs = ["pfsense_d1"]
  source = '''
    .source_site = "device1"
    .host_vm     = "pfsense-d1"
    .lab_zone    = "perimeter"
    .log_type    = "firewall"
    if contains(string(.message) ?? "", "filterlog") {
      parts = split(string(.message) ?? "", ",")
      if length(parts) >= 9 {
        .firewall = {"action":parts[6],"direction":parts[7],"ip_version":parts[8]}
        if parts[8] == "4" && length(parts) >= 20 {
          .firewall.src_ip = parts[18]
          .firewall.dst_ip = parts[19]
        }
      }
    }
  '''

[transforms.suricata_d1_parse]
  type   = "remap"
  inputs = ["suricata_d1"]
  source = '''
    .source_site = "device1"
    .host_vm     = "pfsense-d1"
    .lab_zone    = "perimeter"
    .log_type    = "ids_alert"
    eve, err = parse_json(string(.message) ?? "")
    if err == null {
      .event_type     = string(eve.event_type) ?? ""
      .src_ip         = string(eve.src_ip) ?? ""
      .dst_ip         = string(eve.dest_ip) ?? ""
      if exists(eve.alert) {
        .alert_sig      = string(eve.alert.signature) ?? ""
        .alert_severity = eve.alert.severity
      }
    }
  '''

[sinks.splunk_d1_local]
  type       = "splunk_hec_logs"
  inputs     = ["d1_local_enrich"]
  endpoint   = "http://127.0.0.1:8088"
  token      = "f4b0c50d-d856-4f00-9fa2-51e8ace1a960"
  index      = "main"
  source     = "splunk-vm"
  sourcetype = "journald"
  [sinks.splunk_d1_local.encoding]
    codec = "json"

[sinks.splunk_d1_services]
  type       = "splunk_hec_logs"
  inputs     = ["services_enrich"]
  endpoint   = "http://127.0.0.1:8088"
  token      = "f4b0c50d-xxxx-xxxx-xxxx-51e8ace1a960"
  index      = "main"
  source     = "services-vm"
  sourcetype = "syslog"
  [sinks.splunk_d1_services.encoding]
    codec = "json"

[sinks.splunk_d1_pfsense]
  type       = "splunk_hec_logs"
  inputs     = ["pfsense_d1_enrich"]
  endpoint   = "http://127.0.0.1:8088"
  token      = "f4b0c50d-xxxx-xxxx-xxxx-51e8ace1a960"
  index      = "main"
  source     = "pfsense-d1"
  sourcetype = "pfsense_filterlog"
  [sinks.splunk_d1_pfsense.encoding]
    codec = "json"

[sinks.splunk_d1_suricata]
  type       = "splunk_hec_logs"
  inputs     = ["suricata_d1_parse"]
  endpoint   = "http://127.0.0.1:8088"
  token      = "f4b0c50d-xxxx-xxxx-xxxx-51e8ace1a960"
  index      = "main"
  source     = "suricata-d1"
  sourcetype = "suricata"
  [sinks.splunk_d1_suricata.encoding]
    codec = "json"
```

---

### File: vector.service

**Path:** `/etc/systemd/system/vector.service`
**Host:** collectorvm AND splunk-vm (identical on both)
**Purpose:** Systemd unit file enabling Vector to start on boot and restart automatically on failure.

```ini
[Unit]
Description=Vector log aggregator - ZTA Lab
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vector --config /etc/vector/vector.toml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

---

### File: docker-compose.yml (Splunk)

**Path:** `/opt/splunk/docker-compose.yml`
**Host:** splunk-vm (192.168.10.20)
**Purpose:** Deploys Splunk Enterprise Free 9.3.2 as the lab SIEM. Exposes ports for web UI, HEC ingestion, management API, and Universal Forwarder receiving.

```yaml
services:
  splunk:
    image: splunk/splunk:9.3.2
    container_name: splunk
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=Splunk@123
      - SPLUNK_LICENSE_URI=Free
      - SPLUNK_HEC_TOKEN=f4b0c50d-xxxx-xxxx-xxxx-51e8ace1a960
      - SPLUNK_ENABLE_LISTEN=9997
      - SPLUNK_HTTP_ENABLESSL=false
    ports:
      - "8000:8000"
      - "8088:8088"
      - "8089:8089"
      - "9997:9997"
    volumes:
      - splunk_var:/opt/splunk/var
      - splunk_etc:/opt/splunk/etc
    restart: unless-stopped

volumes:
  splunk_var:
  splunk_etc:
```

**Notes:**
- Port 8000 - Splunk Web UI (proxied via Traefik to splunk.kar1m.site)
- Port 8088 - HEC endpoint receiving Vector events
- Port 8089 - Management API
- Port 9997 - Universal Forwarder receiving
- HEC token pre-configured via environment variable

---

### File: docker-compose.yml (Services Stack)

**Path:** `/opt/services/docker-compose.yml`
**Host:** services-vm (192.168.20.10)
**Purpose:** Deploys the full ZTA enforcement stack - Traefik reverse proxy, Authelia MFA, and cloudflared tunnel - as a single Docker Compose stack.

```yaml
services:

  traefik:
    image: traefik:v2.11
    container_name: traefik
    command:
      - --providers.docker=false
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --entrypoints.web.http.redirections.entrypoint.to=websecure
      - --api.dashboard=true
      - --api.insecure=false
      - --log.level=INFO
    volumes:
      - /opt/services/traefik/config:/etc/traefik/dynamic:ro
      - /opt/services/traefik/certs:/certs:ro
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8080:8080"
    restart: unless-stopped
    networks:
      - proxy

  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    volumes:
      - /opt/services/authelia:/config
    expose:
      - "9091"
    restart: unless-stopped
    networks:
      - proxy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:9091/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared
    command: tunnel --no-autoupdate run
    environment:
      - TUNNEL_TOKEN=${TUNNEL_TOKEN}
    restart: unless-stopped
    networks:
      - proxy

networks:
  proxy:
    external: true
```

**Notes:**
- `--providers.docker=false` is mandatory - Docker socket provider fails silently after container restarts
- Traefik dashboard bound to 127.0.0.1 only - not externally accessible
- All three containers on the same proxy network for internal DNS resolution

---

### File: services.yml (Traefik routes)

**Path:** `/opt/services/traefik/config/services.yml`
**Host:** services-vm (192.168.20.10)
**Purpose:** Defines all HTTP routes, forwardAuth middleware, and backend services for Traefik. Every protected application route passes through Authelia before being proxied.

```yaml
http:
  routers:
    authelia:
      rule: 'Host(`auth.kar1m.site`)'
      entryPoints: [websecure]
      service: authelia-backend
      tls: {}

    splunk:
      rule: 'Host(`splunk.kar1m.site`)'
      entryPoints: [websecure]
      middlewares: [authelia]
      service: splunk-backend
      tls: {}

    app:
      rule: 'Host(`app.kar1m.site`)'
      entryPoints: [websecure]
      middlewares: [authelia]
      service: app-backend
      tls: {}

    traefik-dashboard:
      rule: 'Host(`traefik.kar1m.site`)'
      entryPoints: [websecure]
      middlewares: [authelia]
      service: api@internal
      tls: {}

    fleet-router:
      rule: 'Host(`fleet.kar1m.site`)'
      entryPoints: [websecure]
      service: fleet-service
      tls: {}

  middlewares:
    authelia:
      forwardAuth:
        address: 'http://authelia:9091/api/authz/forward-auth'
        trustForwardHeader: true
        authResponseHeaders:
          - Remote-User
          - Remote-Groups
          - Remote-Name
          - Remote-Email

  services:
    authelia-backend:
      loadBalancer:
        servers:
          - url: 'http://authelia:9091'
    splunk-backend:
      loadBalancer:
        servers:
          - url: 'http://192.168.10.20:8000'
    app-backend:
      loadBalancer:
        servers:
          - url: 'http://192.168.30.50'
    fleet-service:
      loadBalancer:
        servers:
          - url: 'http://192.168.10.20:8220'

  serversTransports:
    insecureTransport:
      insecureSkipVerify: true
```

**Notes:**
- fleet-router has no authelia middleware - agents authenticate via API keys, not TOTP
- auth.kar1m.site has no middleware - Authelia handles its own auth portal
- serversTransport insecureSkipVerify required because backends use self-signed certificates

---

### File: configuration.yml (Authelia)

**Path:** `/opt/services/authelia/configuration.yml`
**Host:** services-vm (192.168.20.10)
**Purpose:** Full Authelia MFA configuration including session management, access control policies, account regulation, and storage settings.

```yaml
server:
  host: 0.0.0.0
  port: 9091

log:
  level: info

jwt_secret: b1cefc3bc59fb09f1516db6b2cfd5fdc703fd0ca512f9fcd765c386de5e43e7d

authentication_backend:
  file:
    path: /config/users_database.yml

session:
  secret: eb8dc16c30d721c54422c75e108c28ef18ca183f2229327d589fab0b667d3f95
  inactivity: 30m
  expiration: 8h
  remember_me: false
  cookies:
    - name: authelia_session
      domain: kar1m.site
      authelia_url: https://auth.kar1m.site
      default_redirection_url: https://splunk.kar1m.site

storage:
  encryption_key: 96ee3a2e2d3e6f49c6ccf6cb3c4d6048b25a6615c9ec55a7ffa3a0b864eca7bc
  local:
    path: /config/db.sqlite3

notifier:
  filesystem:
    filename: /config/notification.txt

access_control:
  default_policy: deny
  rules:
    - domain: auth.kar1m.site
      policy: bypass
    - domain: fleet.kar1m.site
      policy: bypass
    - domain: splunk.kar1m.site
      policy: two_factor
    - domain: "*.kar1m.site"
      policy: two_factor

regulation:
  max_retries: 3
  find_time: 2m
  ban_time: 30m
```

---

### File: users_database.yml (Authelia)

**Path:** `/opt/services/authelia/users_database.yml`
**Host:** services-vm (192.168.20.10)
**Purpose:** Authelia user store. Defines the single lab administrator account with argon2id password hash.

```yaml
users:
  karim:
    displayname: "Karim Abdel-Nasser"
    password: "$argon2id$v=19$m=65536,t=3,p=4$[HASH]"
    email: karim@kar1m.site
    groups:
      - admins
```

---

### File: tls.yml (Traefik)

**Path:** `/opt/services/traefik/config/tls.yml`
**Host:** services-vm (192.168.20.10)
**Purpose:** Configures Traefik to use the self-signed wildcard certificate for all HTTPS routes.

```yaml
tls:
  stores:
    default:
      defaultCertificate:
        certFile: /certs/lab.crt
        keyFile: /certs/lab.key
  options:
    default:
      minVersion: VersionTLS12
```

**Notes:**
- Certificate covers `*.kar1m.site` with SAN entries for `traefik` and `authelia` hostnames
- Cloudflare Public Hostnames have TLS No Verify enabled to trust this self-signed cert
- Minimum TLS 1.2 enforced

---

### File: 99-zta-forward.conf (rsyslog)

**Path:** `/etc/rsyslog.d/99-zta-forward.conf`
**Host:** appserver-vm, user-vm-1, user-vm-2 (identical on all three)
**Purpose:** Forwards all syslog events - including auth and privilege events - to collectorvm Vector on UDP 514.

```bash
# ZTA Lab - Forward ALL logs to collectorvm Vector
auth,authpriv.*  @192.168.30.100:514
*.*              @192.168.30.100:514
```

**Notes:**
- `auth,authpriv.*` is declared explicitly before `*.*` to ensure SSH and PAM events are never dropped
- Single `@` = UDP (no acknowledgement) - appropriate for lab environment
- `/var/lib/rsyslog/` must exist before restarting rsyslog or forwarding breaks silently

**Prerequisite command:**
```bash
sudo mkdir -p /var/lib/rsyslog
sudo chown syslog:syslog /var/lib/rsyslog
```

---

### File: 99-zta-forward.conf (rsyslog D1)

**Path:** `/etc/rsyslog.d/99-zta-forward.conf`
**Host:** services-vm (192.168.20.10)
**Purpose:** Forwards services-vm syslog events to Vector D1 on splunk-vm UDP 514.

```bash
# ZTA Lab - Forward service logs to splunk-vm Vector D1
auth,authpriv.*  @192.168.10.20:514
*.*              @192.168.10.20:514
```

---

### File: netplan config - appserver-vm

**Path:** `/etc/netplan/00-installer-config.yaml`
**Host:** appserver-vm (192.168.30.50)
**Purpose:** Configures VLAN 30 tagging on the trunk-d2 internal network interface.

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
  vlans:
    enp0s3.30:
      id: 30
      link: enp0s3
      addresses: [192.168.30.50/24]
      routes:
        - to: default
          via: 192.168.30.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

---

### File: netplan config - user-vm-1

**Path:** `/etc/netplan/00-installer-config.yaml`
**Host:** user-vm-1 (192.168.30.10)

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
  vlans:
    enp0s3.30:
      id: 30
      link: enp0s3
      addresses: [192.168.30.10/24]
      routes:
        - to: default
          via: 192.168.30.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

---

### File: netplan config - user-vm-2

**Path:** `/etc/netplan/00-installer-config.yaml`
**Host:** user-vm-2 (192.168.30.20)

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
  vlans:
    enp0s3.30:
      id: 30
      link: enp0s3
      addresses: [192.168.30.20/24]
      routes:
        - to: default
          via: 192.168.30.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

---

### File: netplan config - collectorvm

**Path:** `/etc/netplan/00-installer-config.yaml`
**Host:** collectorvm (192.168.30.100)

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
  vlans:
    enp0s3.30:
      id: 30
      link: enp0s3
      addresses: [192.168.30.100/24]
      routes:
        - to: default
          via: 192.168.30.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

---

### File: netplan config - kali-vm

**Path:** `/etc/netplan/00-installer-config.yaml`
**Host:** kali-vm (192.168.40.10)
**Notes:** Kali uses eth0 not enp0s3

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
  vlans:
    eth0.40:
      id: 40
      link: eth0
      addresses: [192.168.40.10/24]
      routes:
        - to: default
          via: 192.168.40.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

---

### File: zta-lab.rules (auditd)

**Path:** `/etc/audit/rules.d/zta-lab.rules`
**Host:** appserver-vm (192.168.30.50)
**Purpose:** Kernel-level audit rules that capture syscall-level events an attacker cannot evade by clearing shell history. Provides visibility into command execution, file access, network connections, and privilege operations.

```bash
# ZTA Lab - auditd rules for appserver-vm
-D
-b 8192
-f 1

# Identity files
-w /etc/passwd -p rwxa -k identity
-w /etc/shadow -p rwxa -k identity
-w /etc/group  -p rwxa -k identity

# Privilege escalation
-w /etc/sudoers    -p rwxa -k privesc
-w /etc/sudoers.d/ -p rwxa -k privesc

# Command execution (execve syscall)
-a always,exit -F arch=b64 -S execve -k cmd_exec
-a always,exit -F arch=b32 -S execve -k cmd_exec

# Network connections
-a always,exit -F arch=b64 -S connect -k net_connect
-a always,exit -F arch=b64 -S bind    -k net_bind

# Suspicious paths
-w /tmp      -p rwxa -k tmp_access
-w /dev/shm  -p rwxa -k shm_access

# Attack tool monitoring
-w /bin/nc        -p rwxa -k netcat
-w /usr/bin/nc    -p rwxa -k netcat
-w /bin/bash      -p rwxa -k shell_access
-w /opt/dvwa/     -p rwxa -k dvwa_access

# Privilege change syscalls
-a always,exit -F arch=b64 -S setuid  -k setuid
-a always,exit -F arch=b64 -S chmod   -k permission_change
-a always,exit -F arch=b64 -S chown   -k ownership_change
```

---

### File: syslog.conf (audisp plugin)

**Path:** `/etc/audisp/plugins.d/syslog.conf`
**Host:** appserver-vm (192.168.30.50)
**Purpose:** Enables the audisp-syslog plugin so auditd events are fed into rsyslog and forwarded to collectorvm along with all other syslog events.

```ini
active     = yes
direction  = out
path       = builtin_syslog
type       = builtin
args       = LOG_INFO
format     = string
```

---

### File: docker-compose.yml (DVWA)

**Path:** `/opt/dvwa/docker-compose.yml`
**Host:** appserver-vm (192.168.30.50)
**Purpose:** Deploys DVWA (Damn Vulnerable Web Application) as the primary web attack target. Runs Apache and MariaDB as separate containers.

```yaml
services:
  dvwa:
    image: ghcr.io/digininja/dvwa:latest
    restart: always
    ports:
      - "80:80"
    environment:
      - DB_SERVER=db
      - DB_PORT=3306
      - DB_DATABASE=dvwa
      - DB_USERNAME=dvwa
      - DB_PASSWORD=p@ssw0rd
    depends_on:
      - db

  db:
    image: mariadb:10
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    volumes:
      - dvwa_db:/var/lib/mysql

volumes:
  dvwa_db:
```

---

### File: dvwa.service

**Path:** `/etc/systemd/system/dvwa.service`
**Host:** appserver-vm (192.168.30.50)
**Purpose:** Starts DVWA automatically on boot via Docker Compose.

```ini
[Unit]
Description=DVWA - ZTA Lab Attack Target
After=docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/dvwa
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

### File: daemon.json (Docker log driver)

**Path:** `/etc/docker/daemon.json`
**Host:** appserver-vm (192.168.30.50)
**Purpose:** Configures Docker to use journald as the log driver so DVWA container stdout/stderr is captured by rsyslog and forwarded to Vector.

```json
{
  "log-driver": "journald",
  "log-opts": {
    "tag": "{{.Name}}"
  }
}
```

---

### File: Splunk Detection Rules (SPL)

**Path:** Splunk Web UI - Dashboards and Saved Searches
**Host:** splunk-vm (192.168.10.20) - browser at splunk.kar1m.site
**Purpose:** 10 custom SPL detection rules mapped to MITRE ATT&CK techniques.

```spl
-- Rule 1: SSH Brute Force - T1110.001
index=main auth_event=ssh_fail
| stats count as attempts by ssh.src_ip, ssh.user, host
| where attempts >= 5
| eval severity=if(attempts>=20, "CRITICAL", "HIGH")
| eval mitre="T1110.001"
| sort -attempts

-- Rule 2: Brute Force to Valid Account - T1110 to T1078
index=main (auth_event=ssh_fail OR auth_event=ssh_success)
| eval action=if(auth_event="ssh_fail", "FAIL", "SUCCESS")
| stats values(action) as actions, count by src_ip, host
| where like(mvjoin(actions,","),"%FAIL%") AND like(mvjoin(actions,","),"%SUCCESS%")
| eval severity="CRITICAL", mitre="T1110 to T1078"

-- Rule 3: Suricata Critical Alert - T1595/T1190
index=main log_type=ids_alert alert_severity=1
| stats count by src_ip, dst_ip, alert_sig, alert_category
| sort -count

-- Rule 4: Port Scan from VLAN40 - T1046
index=main log_type=ids_alert src_ip="192.168.40.10"
| stats dc(dst_port) as ports_scanned by src_ip
| where ports_scanned >= 15
| eval severity="HIGH", mitre="T1046"

-- Rule 5: Privilege Escalation via Sudo - T1548.003
index=main auth_event=sudo sudo.run_as=root
| stats count by sudo.user, sudo.cmd, host
| eval severity="HIGH", mitre="T1548.003"

-- Rule 6: Off-Hours Authentication - T1078
index=main auth_event=ssh_success
| eval hour=strftime(_time, "%H")
| where hour < "07" OR hour > "22"
| eval severity="MEDIUM", mitre="T1078"

-- Rule 7: Attacker VLAN Reaching MGMT - T1021
index=main log_type=firewall
| search firewall.src_ip="192.168.40.*"
| search firewall.dst_ip="192.168.10.*" OR firewall.dst_ip="192.168.20.*"
| search firewall.action="pass"
| eval severity="CRITICAL", mitre="T1021"

-- Rule 8: Full Kill Chain Correlation
index=main earliest=-60m
| eval stage=case(
    log_type="ids_alert" AND like(alert_sig,"%scan%"), "1_RECON",
    auth_event="ssh_fail",                              "2_BRUTE",
    auth_event="ssh_success",                           "3_ACCESS",
    log_type="audit" AND like(message,"%git%"),         "4_TOOL_DL",
    log_type="audit" AND like(message,"%execve%"),      "5_EXEC",
    auth_event="sudo",                                  "6_ESCALATE",
    log_type="audit" AND like(message,"%shadow%"),      "7_CRED",
    log_type="audit" AND like(message,"%crontab%"),     "8_PERSIST",
    log_type="audit" AND like(message,"%HISTFILE%"),    "9_EVASION",
    true(), "OTHER")
| where stage != "OTHER"
| stats values(stage) as kill_chain_stages, count by host
| eval total_stages=mvcount(kill_chain_stages)
| where total_stages >= 3
| eval verdict="HIGH CONFIDENCE COMPROMISE"

-- Rule 9: auditd Command Execution - T1059.004
index=main log_type=audit audit_event=cmd_exec
| rex field=message "exe=\"(?P<executable>[^\"]+)\""
| where executable IN ("/bin/bash","/bin/sh","/usr/bin/python3","/bin/nc","/usr/bin/curl","/usr/bin/wget")
| stats count by executable, host
| eval severity="HIGH", mitre="T1059.004"

-- Rule 10: SQL Injection Detection - T1190
index=main log_type=ids_alert
| search alert_sig=*sql* OR alert_sig=*injection* OR alert_sig=*sqlmap*
| stats count by src_ip, dst_ip, alert_sig
| eval severity="HIGH", mitre="T1190"
```

---

### File: Cloudflare WAF Rules

**Location:** Cloudflare Dashboard - Security - WAF - Custom Rules
**Host:** Cloudflare edge (not on-premises)
**Purpose:** Four custom WAF rules providing edge-level attack blocking before traffic reaches the tunnel.

```
Rule 1 - Block Attack Tool User-Agents
Expression:
(http.user_agent contains "sqlmap") or
(http.user_agent contains "nikto") or
(http.user_agent contains "nmap") or
(http.user_agent contains "hydra") or
(http.user_agent contains "gobuster") or
(http.user_agent contains "masscan")
Action: Block

Rule 2 - Geo Restriction - Egypt Only
Expression:
(ip.geoip.country ne "EG") and
(http.host eq "splunk.kar1m.site" or
 http.host eq "app.kar1m.site" or
 http.host eq "traefik.kar1m.site")
Action: Block

Rule 3 - Basic OWASP Signatures
Expression:
(http.request.uri.query contains "UNION SELECT") or
(http.request.uri.query contains "OR 1=1") or
(http.request.uri.query contains "DROP TABLE") or
(http.request.uri.query contains "etc/passwd") or
(http.request.uri.query contains "<script>")
Action: Block

Rule 4 - Rate Limiting
Expression: (http.host eq "app.kar1m.site") or (http.host eq "traefik.kar1m.site")
Threshold: 30 requests per 10 seconds
Action: Block for 1 minute
```

---

### File: targets.txt (kali attack workspace)

**Path:** `~/lab-attacks/targets.txt`
**Host:** kali-vm (192.168.40.10)
**Purpose:** Reference file documenting authorized attack targets and credentials for the lab simulation.

```
# ZTA Lab - Authorized Attack Targets ONLY
192.168.30.10   user-vm-1   ssh: bob/Password123, svc_backup/Backup@2024
192.168.30.20   user-vm-2   ssh: carol/Password123
192.168.30.50   appserver   http:80 DVWA, ssh: alice/Password123
```

---

### File: full_killchain.sh (kali attack script)

**Path:** `~/lab-attacks/full_killchain.sh`
**Host:** kali-vm (192.168.40.10)
**Purpose:** Automated kill chain script executing reconnaissance, brute force, and web application attack phases from kali-vm.

```bash
#!/bin/bash
TARGET="192.168.30.50"

echo "[PHASE 1] Reconnaissance - T1046"
nmap -sS -p 22,80,3306 $TARGET --open \
  -oN ~/lab-attacks/recon/nmap_appserver.txt

echo "[PHASE 1] Web Fingerprint - T1592"
nikto -h http://$TARGET \
  -o ~/lab-attacks/recon/nikto_appserver.txt &

echo "[PHASE 2] SSH Brute Force - T1110.001"
hydra -l alice \
  -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  $TARGET ssh -t 4 -f \
  -o ~/lab-attacks/recon/hydra_results.txt 2>/dev/null

echo "[PHASE 2] SQL Injection - T1190"
sqlmap -u "http://$TARGET/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=test; security=low" \
  --dbs --batch \
  --output-dir=~/lab-attacks/exploitation/sqlmap/ &>/dev/null

echo "[*] Remote phases complete. Manual steps:"
echo "    ssh alice@$TARGET (Password123)"
echo "    sudo bash"
echo "    cat /etc/shadow"
```

---

## 3. Files by Category

### Logging and Monitoring

| File | Host | Path |
|---|---|---|
| vector.toml (D2) | collectorvm | /etc/vector/vector.toml |
| vector.toml (D1) | splunk-vm | /etc/vector/vector.toml |
| vector.service | both | /etc/systemd/system/vector.service |
| 99-zta-forward.conf | appserver, user-vm-1, user-vm-2 | /etc/rsyslog.d/99-zta-forward.conf |
| 99-zta-forward.conf (D1) | services-vm | /etc/rsyslog.d/99-zta-forward.conf |
| docker-compose.yml (Splunk) | splunk-vm | /opt/splunk/docker-compose.yml |
| Splunk SPL rules | splunk-vm UI | splunk.kar1m.site |

### Network and Segmentation

| File | Host | Path |
|---|---|---|
| netplan - appserver-vm | appserver-vm | /etc/netplan/00-installer-config.yaml |
| netplan - user-vm-1 | user-vm-1 | /etc/netplan/00-installer-config.yaml |
| netplan - user-vm-2 | user-vm-2 | /etc/netplan/00-installer-config.yaml |
| netplan - collectorvm | collectorvm | /etc/netplan/00-installer-config.yaml |
| netplan - kali-vm | kali-vm | /etc/netplan/00-installer-config.yaml |

### Detection and Security

| File | Host | Path |
|---|---|---|
| zta-lab.rules (auditd) | appserver-vm | /etc/audit/rules.d/zta-lab.rules |
| syslog.conf (audisp) | appserver-vm | /etc/audisp/plugins.d/syslog.conf |
| Cloudflare WAF rules | Cloudflare edge | Dashboard only |

### Authentication and Access Control

| File | Host | Path |
|---|---|---|
| configuration.yml | services-vm | /opt/services/authelia/configuration.yml |
| users_database.yml | services-vm | /opt/services/authelia/users_database.yml |
| Cloudflare Access policies | Cloudflare edge | Dashboard only |

### Reverse Proxy and Exposure

| File | Host | Path |
|---|---|---|
| docker-compose.yml (services) | services-vm | /opt/services/docker-compose.yml |
| services.yml (Traefik routes) | services-vm | /opt/services/traefik/config/services.yml |
| tls.yml | services-vm | /opt/services/traefik/config/tls.yml |
| lab.crt | services-vm | /opt/services/traefik/certs/lab.crt |
| lab.key | services-vm | /opt/services/traefik/certs/lab.key |

### Attack Simulation

| File | Host | Path |
|---|---|---|
| full_killchain.sh | kali-vm | ~/lab-attacks/full_killchain.sh |
| targets.txt | kali-vm | ~/lab-attacks/targets.txt |

### Application Layer

| File | Host | Path |
|---|---|---|
| docker-compose.yml (DVWA) | appserver-vm | /opt/dvwa/docker-compose.yml |
| daemon.json | appserver-vm | /etc/docker/daemon.json |
| dvwa.service | appserver-vm | /etc/systemd/system/dvwa.service |

---

## 4. Architecture File Mapping

```
splunk-vm (192.168.10.20 - VLAN10)
├── /opt/splunk/docker-compose.yml
├── /opt/splunk/.env
├── /etc/vector/vector.toml
└── /etc/systemd/system/vector.service

services-vm (192.168.20.10 - VLAN20)
├── /opt/services/docker-compose.yml
├── /opt/services/.env
├── /opt/services/traefik/config/services.yml
├── /opt/services/traefik/config/tls.yml
├── /opt/services/traefik/certs/lab.crt
├── /opt/services/traefik/certs/lab.key
├── /opt/services/authelia/configuration.yml
├── /opt/services/authelia/users_database.yml
└── /etc/rsyslog.d/99-zta-forward.conf

appserver-vm (192.168.30.50 - VLAN30)
├── /opt/dvwa/docker-compose.yml
├── /etc/systemd/system/dvwa.service
├── /etc/docker/daemon.json
├── /etc/audit/rules.d/zta-lab.rules
├── /etc/audisp/plugins.d/syslog.conf
├── /etc/netplan/00-installer-config.yaml
└── /etc/rsyslog.d/99-zta-forward.conf

user-vm-1 (192.168.30.10 - VLAN30)
├── /etc/netplan/00-installer-config.yaml
└── /etc/rsyslog.d/99-zta-forward.conf

user-vm-2 (192.168.30.20 - VLAN30)
├── /etc/netplan/00-installer-config.yaml
└── /etc/rsyslog.d/99-zta-forward.conf

collectorvm (192.168.30.100 - VLAN30)
├── /etc/vector/vector.toml
├── /etc/systemd/system/vector.service
├── /var/lib/vector/
└── /etc/netplan/00-installer-config.yaml

kali-vm (192.168.40.10 - VLAN40)
├── /etc/netplan/00-installer-config.yaml
├── /etc/hosts
├── ~/lab-attacks/targets.txt
└── ~/lab-attacks/full_killchain.sh

pfSense-D1 / pfSense-D2
└── Configured via WebGUI (192.168.56.1 / 192.168.56.2)
    - VLAN interfaces
    - Firewall rules
    - IPsec Phase 1 + Phase 2
    - Suricata EVE JSON syslog output
    - System syslog remote forwarding
```

---

## 5. Security Flow Mapping

### External Legitimate Access Flow

```
Browser (WARP enrolled, Egypt IP)
  - Cloudflare evaluates: identity + country + device posture
  - WAF checks User-Agent and request signatures
  - Access policy allows: forward to cloudflared tunnel
  - cloudflared proxies to Traefik on services-vm:443
  - Traefik forwardAuth sends request to Authelia:9091
  - No valid session: Authelia redirects to auth.kar1m.site
  - User provides credentials + TOTP code
  - Authelia creates session, redirects back
  - Traefik proxies to backend (splunk-vm:8000 or appserver:80)
  - Access granted with session (8h max, 30min inactivity)
```

### Attack Detection Flow (kali-vm)

```
kali-vm (192.168.40.10)
  - nmap SYN scan against 192.168.30.0/24
      -> pfSense-D2 passes (VLAN40->VLAN30 allowed)
      -> Suricata-D2 detects scan signature
      -> EVE JSON via syslog UDP:516 to collectorvm
      -> Vector parses EVE JSON: alert_sig, alert_severity
      -> Splunk HEC via IPsec: log_type=ids_alert
      -> Splunk Rule 4 fires: Port Scan from VLAN40

  - hydra SSH brute force against appserver-vm
      -> SSH daemon on appserver-vm logs Failed password
      -> rsyslog forwards via UDP:514 to collectorvm
      -> Vector parses: auth_event=ssh_fail, ssh.src_ip, ssh.user
      -> Splunk HEC: log_type=auth
      -> Splunk Rule 1 fires: SSH Brute Force (>=5 attempts)

  - ssh alice@192.168.30.50 (successful)
      -> SSH daemon logs Accepted password
      -> rsyslog -> collectorvm -> Vector -> Splunk
      -> Splunk Rule 2 fires: Brute Force then Valid Account

kali-vm attempts 192.168.10.20 (splunk-vm)
  - pfSense-D1 IPsec rules: VLAN40 -> VLAN10 = BLOCK
  - pfSense filterlog records dropped packet
  - syslog UDP:515 -> Vector D1 on splunk-vm
  - Splunk: firewall.src_ip=192.168.40.10, firewall.dst_ip=192.168.10.20, action=block
  - Splunk Rule 7: Attacker VLAN Reaching MGMT
```

### Post-Exploitation Detection Flow (inside appserver-vm)

```
alice@appserver-vm
  - sudo bash
      -> rsyslog captures sudo event
      -> Vector parses: sudo.user=alice, sudo.run_as=root, sudo.cmd=/bin/bash
      -> Splunk Rule 5 fires: Privilege Escalation via Sudo

  - git clone / curl (tool download)
      -> auditd captures execve syscall
      -> audisp-syslog feeds to rsyslog
      -> rsyslog -> collectorvm -> Vector -> Splunk
      -> Splunk Rule 9 fires: auditd Command Execution

  - cat /etc/shadow
      -> auditd captures file open() on /etc/shadow (configured audit rule)
      -> Splunk: log_type=audit, message contains "shadow"
      -> Kill chain Rule 8: stage 7_CRED registered

  - history -c, unset HISTFILE
      -> auditd captures execve on bash with HISTFILE argument
      -> Splunk still sees the evasion attempt
      -> Kill chain Rule 8: stage 9_EVASION registered

```

---

## 6. MITRE ATT&CK Mapping

| File / Script / Tool | Technique ID | Technique Name |
|---|---|---|
| full_killchain.sh - nmap | T1046 | Network Service Discovery |
| full_killchain.sh - nikto | T1592 | Gather Victim Host Information |
| full_killchain.sh - hydra | T1110.001 | Brute Force: Password Guessing |
| full_killchain.sh - sqlmap | T1190 | Exploit Public-Facing Application |
| ssh login with found creds | T1078 | Valid Accounts |
| git clone / curl in /tmp | T1105 | Ingress Tool Transfer |
| cat /etc/passwd | T1087.001 | Account Discovery: Local Account |
| find / -type f | T1083 | File and Directory Discovery |
| sudo bash | T1548.003 | Abuse Elevation Control: Sudo |
| cat /etc/shadow | T1003.008 | OS Credential Dumping: /etc/passwd |
| ~/.ssh/authorized_keys write | T1098 | Account Manipulation |
| crontab persistence entry | T1053.003 | Scheduled Task/Job: Cron |
| ssh bob@192.168.30.10 | T1021.004 | Remote Services: SSH |
| nc exfiltration to kali | T1041 | Exfiltration Over C2 Channel |
| history -c, unset HISTFILE | T1070.003 | Indicator Removal: Clear Command History |

---

## 7. Credential Reference

| System | Username | Password | Notes |
|---|---|---|---|
| Splunk Web | admin | Splunk@123 | splunk.kar1m.site |
| Authelia | karim | 123456 | TOTP enrolled |
| appserver-vm SSH | alice | Password123 | sudo access |
| user-vm-1 SSH | bob | Password123 | sudo access |
| user-vm-1 SSH | svc_backup | Backup@2024 | no sudo - lateral movement target |
| user-vm-2 SSH | carol | Password123 | sudo access |
| DVWA web | admin | password | default - change after setup.php |
| DVWA MariaDB | dvwa | p@ssw0rd | app database |
| DVWA MariaDB root | root | dvwa | SQLi target |
| Splunk HEC token | - | f4b0c50d-xxxx-xxxx-xxxx-51e8ace1a960 | Vector authentication |
| Cloudflare Tunnel UUID | - | fcf78abe-xxxx-xxxx-xxxx-xxxxxxxxxx | homelab tunnel |

---

*Stack: Splunk 9.3.2 - Vector 0.55.0 - Traefik v2.11 - Authelia - pfSense 2.7 - Suricata - Cloudflare Zero Trust - Docker - Ubuntu 22.04/24.04 - Kali Linux 2024*

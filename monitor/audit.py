"""Stage 4: security audit of Cisco IOS running-configs.

Runs on the RAW config right after the daily backup (and on demand with --audit), so it can see
password types and community strings. Evidence lines are redacted before anything is stored or
emailed; the fix commands use placeholders - the agent never sees or writes a real secret.

Each rule yields Findings with a severity, the offending line(s), an explanation and the exact
IOS commands to fix it. The lifecycle (new / still open / resolved) is tracked in history.db.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .diagnose import redact

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
WEAK_WORDS = {"public", "private", "cisco", "admin", "password", "secret", "snmp", "community", "manager",
              "monitor", "default", "read", "write", "123456", "12345678", "qwerty", "letmein", "guest", "test",
              "router", "switch", "cisco123", "admin123", "changeme"}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    fix: list[str]
    evidence: list[str] = field(default_factory=list)   # redacted config lines
    device: str = ""

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.device}|{self.rule}|{self.title}|{'|'.join(sorted(self.evidence))}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "title": self.title, "detail": self.detail,
                "fix": self.fix, "evidence": self.evidence, "device": self.device, "fingerprint": self.fingerprint}


# --------------------------------------------------------------------------- config model
class Config:
    """Minimal IOS config model: top-level lines plus indented blocks (interface, line, router, ...)."""

    def __init__(self, text: str):
        self.text = text
        self.lines = [ln.rstrip() for ln in text.splitlines()]
        self.blocks: dict[str, list[str]] = {}
        cur = None
        for ln in self.lines:
            if not ln.strip() or ln.strip() == "!":
                cur = None
                continue
            if ln.startswith(" "):
                if cur is not None:
                    self.blocks.setdefault(cur, []).append(ln.strip())
            else:
                cur = ln.strip()
                self.blocks.setdefault(cur, [])

    def top(self, pattern: str) -> list[str]:
        rx = re.compile(pattern, re.I)
        return [ln for ln in self.lines if not ln.startswith(" ") and rx.search(ln)]

    def has(self, pattern: str) -> bool:
        return bool(self.top(pattern))

    def block(self, header_pattern: str) -> dict[str, list[str]]:
        rx = re.compile(header_pattern, re.I)
        return {h: b for h, b in self.blocks.items() if rx.match(h)}

    def wan_interfaces(self, names: Iterable[str]) -> dict[str, list[str]]:
        want = {n.lower() for n in names}
        return {h: b for h, b in self.blocks.items() if h.lower().startswith("interface ") and h.split(" ", 1)[1].lower() in want}


# --------------------------------------------------------------------------- rules
Rule = Callable[[Config, dict], list[Finding]]
RULES: list[tuple[str, Rule]] = []


def rule(rid: str):
    def deco(fn):
        RULES.append((rid, fn))
        return fn
    return deco


def _f(rid, sev, title, detail, fix, evidence=()):
    return Finding(rid, sev, title, detail, list(fix), [redact(e) for e in evidence])


@rule("enable_password")
def r_enable_password(c: Config, ctx: dict):
    ev = c.top(r"^enable password\b")
    if not ev:
        return []
    has_secret = c.has(r"^enable secret\b")
    return [_f("enable_password", "critical", "Enable password stored reversibly (enable password)",
               "`enable password` is stored in cleartext or type-7, which is decoded in seconds by anyone who sees the "
               "config (backups, show tech, shoulder-surfing)." + ("" if has_secret else " There is no `enable secret` either."),
               ["enable algorithm-type scrypt secret <NEW-STRONG-SECRET>", "no enable password", "write memory"], ev)]


_PPP_RE = re.compile(r"^\s*ppp\s+(chap|pap)\b", re.I)


def _is_ppp(ln: str) -> bool:
    return bool(_PPP_RE.match(ln))


@rule("type7_passwords")
def r_type7(c: Config, ctx: dict):
    hits = [ln for ln in c.lines if re.search(r"\b(password|key|key-string)\s+7\s+\S+", ln) and not ln.lstrip().startswith("enable password")]
    ev = [ln for ln in hits if not _is_ppp(ln)]
    ppp = [ln for ln in hits if _is_ppp(ln)]
    out = []
    if ev:
        out.append(_f("type7_passwords", "high", f"{len(ev)} type-7 (reversible) password(s)/key(s)",
                      "Type 7 is obfuscation, not encryption - the original value is recovered instantly. Replace with `secret` "
                      "(type 8/9) where IOS supports it, or rotate the key if the protocol only supports type 7 (keep it off shared docs).",
                      ["! user accounts:", "username <NAME> privilege 15 algorithm-type scrypt secret <NEW-STRONG-SECRET>",
                       "! for each username that only has 'password 7': add the secret, then", "no username <NAME> password",
                       "write memory"], ev))
    if ppp:
        out.append(_f("ppp_credentials", "low", f"{len(ppp)} PPP CHAP/PAP credential(s) stored as type 7",
                      "PPP CHAP/PAP must store the ISP password reversibly (the router sends it to the ISP), so type 7 is the "
                      "best IOS can do - this is expected. Keep config backups and 'show run' output private, and rotate the "
                      "ISP password if a config was ever shared. Accept this finding once reviewed.",
                      ["! nothing to change on the router; review and then:",
                       "! docker compose run --rm cisco-g0-monitor --accept <router> \"PPP CHAP/PAP credential\" --reason \"required by ISP link\""],
                      ppp))
    return out


@rule("plaintext_passwords")
def r_plaintext(c: Config, ctx: dict):
    hits = [ln for ln in c.lines if re.search(r"\b(password|key)\s+0\s+\S+", ln)
            or re.search(r"^username\s+\S+(\s+privilege\s+\d+)?\s+password\s+(?!\d\s)\S+", ln.strip())
            or re.search(r"^\s*password\s+(?![05789]\s)\S+$", ln)
            or (_is_ppp(ln) and re.search(r"\bpassword\s+(?![57]\s)\S+", ln))]
    ev = [ln for ln in hits if not _is_ppp(ln)]
    ppp = [ln for ln in hits if _is_ppp(ln)]
    out = []
    if ev:
        weak = []
        for ln in ev:
            m = re.search(r"(?:password|key)\s+(?:0\s+)?(\S+)\s*$", ln.strip())
            if m and (len(m.group(1)) < 8 or m.group(1).lower() in WEAK_WORDS):
                weak.append(ln)
        detail = ("Passwords stored in cleartext. Anyone with read access to the config has them."
                  + (f" {len(weak)} of them are also short or a common word." if weak else ""))
        out.append(_f("plaintext_passwords", "critical", f"{len(ev)} cleartext password(s)", detail,
                      ["service password-encryption", "username <NAME> privilege 15 algorithm-type scrypt secret <NEW-STRONG-SECRET>",
                       "no username <NAME> password", "line vty 0 4", " login local", "write memory"], ev))
    if ppp:
        pap = any(re.search(r"\bppp\s+pap\b", ln, re.I) for ln in ppp)
        out.append(_f("ppp_cleartext", "high", f"{len(ppp)} PPP CHAP/PAP password(s) in cleartext",
                      "The router's ISP/link password is readable by anyone who sees the config. PPP needs a reversible password, "
                      "so it cannot be hashed - but `service password-encryption` turns it into type 7, which keeps it out of "
                      "casual view (screens, tickets, backups)."
                      + (" PAP also sends the password unencrypted to the other end; if the ISP supports CHAP, use CHAP only." if pap else ""),
                      ["service password-encryption",
                       "! if the ISP supports CHAP, on the Dialer/PPP interface:",
                       "!   ppp authentication chap callin",
                       "!   no ppp pap sent-username",
                       "write memory",
                       "! if this config was ever emailed or shared, ask the ISP to change the password"],
                      ppp))
    return out


@rule("md5_secrets")
def r_md5(c: Config, ctx: dict):
    ev = [ln for ln in c.lines if re.search(r"\bsecret\s+5\s+\S+", ln)]
    if not ev:
        return []
    return [_f("md5_secrets", "low", f"{len(ev)} MD5 (type 5) secret(s)",
               "Type 5 is salted MD5 - fine against casual exposure but fast to brute-force offline. IOS 15.3+ supports "
               "scrypt (type 9); re-enter the secrets to upgrade them.",
               ["enable algorithm-type scrypt secret <SAME-OR-NEW-SECRET>",
                "username <NAME> privilege 15 algorithm-type scrypt secret <SAME-OR-NEW-SECRET>", "write memory"], ev)]


@rule("no_password_encryption")
def r_svc_pwd_enc(c: Config, ctx: dict):
    if c.has(r"^service password-encryption$"):
        return []
    return [_f("no_password_encryption", "low", "service password-encryption is off",
               "Without it, any `password` entered later lands in the config in cleartext.",
               ["service password-encryption", "write memory"])]


@rule("vty_telnet")
def r_vty_telnet(c: Config, ctx: dict):
    out = []
    for h, b in c.block(r"^line vty").items():
        ti = [x for x in b if x.startswith("transport input")]
        if not ti:
            out.append(_f("vty_telnet", "high", f"{h}: no 'transport input' (Telnet allowed by default)",
                          "Classic IOS accepts Telnet on vty lines unless restricted. Telnet sends the login in cleartext.",
                          [h, " transport input ssh", "write memory"], [h]))
        elif any(re.search(r"transport input (all|telnet)", x) for x in ti):
            out.append(_f("vty_telnet", "high", f"{h}: Telnet enabled ({ti[0]})",
                          "Telnet sends usernames and passwords in cleartext across the LAN.",
                          [h, " transport input ssh", "write memory"], [f"{h} / {ti[0]}"]))
    return out


@rule("vty_no_acl")
def r_vty_acl(c: Config, ctx: dict):
    out = []
    for h, b in c.block(r"^line vty").items():
        if not any(x.startswith("access-class") for x in b):
            out.append(_f("vty_no_acl", "medium", f"{h}: no access-class (management open to any source)",
                          "Anyone who can reach the router's IP can attempt SSH logins. Restrict to the management subnet.",
                          ["ip access-list standard MGMT", " permit <MGMT-SUBNET> <WILDCARD>", " deny any log",
                           h, " access-class MGMT in", "write memory"], [h]))
    return out


@rule("exec_timeout")
def r_exec_timeout(c: Config, ctx: dict):
    out = []
    for h, b in c.block(r"^line (vty|con|aux)").items():
        et = [x for x in b if x.startswith("exec-timeout")]
        if any(x == "exec-timeout 0 0" for x in et):
            out.append(_f("exec_timeout", "medium", f"{h}: exec-timeout 0 0 (sessions never expire)",
                          "An idle admin session stays logged in forever - a left-open terminal is a privileged session for anyone.",
                          [h, " exec-timeout 10 0", "write memory"], [f"{h} / exec-timeout 0 0"]))
        # No exec-timeout line means the IOS default (10 min), which is fine - IOS hides default values.
    return out


@rule("aux_exec")
def r_aux(c: Config, ctx: dict):
    for h, b in c.block(r"^line aux").items():
        if "no exec" not in b:
            return [_f("aux_exec", "low", "AUX port allows an exec session",
                       "The AUX port is rarely used; a modem or console cable on it gives a login prompt.",
                       [h, " no exec", " transport input none", "write memory"], [h])]
    return []


@rule("http_server")
def r_http(c: Config, ctx: dict):
    out = []
    if c.has(r"^ip http server$"):
        out.append(_f("http_server", "high", "HTTP management server enabled (cleartext)",
                      "The web UI over HTTP sends the admin login in cleartext. Disable it; use HTTPS only if you need the web UI at all.",
                      ["no ip http server", "write memory"], ["ip http server"]))
    if c.has(r"^ip http secure-server$") and not c.has(r"^ip http access-class"):
        out.append(_f("http_server", "medium", "HTTPS management server enabled without an access-class",
                      "Fine if you use the web UI, but restrict who can reach it (or disable it if you only use SSH).",
                      ["ip http access-class <ACL-NUMBER>", "! or simply:", "no ip http secure-server", "write memory"],
                      ["ip http secure-server"]))
    return out


@rule("snmp")
def r_snmp(c: Config, ctx: dict):
    out = []
    comms = c.top(r"^snmp-server community\b")
    for ln in comms:
        m = re.match(r"snmp-server community\s+(\S+)(?:\s+(view\s+\S+))?\s*(RO|RW)?\s*(\d+|\S+)?", ln, re.I)
        name = m.group(1) if m else "?"
        mode = (m.group(3) or "RO").upper() if m else "RO"
        acl = m.group(4) if m else None
        weak = name.lower() in WEAK_WORDS or len(name) < 8
        if mode == "RW":
            out.append(_f("snmp", "critical", "SNMP community with WRITE access",
                          "A read-write community string lets anyone who knows it reconfigure the router (even upload a config).",
                          ["no snmp-server community <COMMUNITY> RW", "! if write access is really needed, use SNMPv3 with auth+priv",
                           "write memory"], [ln]))
        if weak:
            out.append(_f("snmp", "critical" if mode == "RW" else "high", "Weak or default SNMP community string",
                          "Default or short community strings are the first thing scanners try; SNMPv2c "
                          "also sends the string in cleartext.",
                          ["no snmp-server community <COMMUNITY>", "snmp-server group V3GRP v3 priv",
                           "snmp-server user <USER> V3GRP v3 auth sha <AUTH-PASS> priv aes 128 <PRIV-PASS>", "write memory"], [ln]))
        elif not acl and mode != "RW":
            out.append(_f("snmp", "medium", "SNMPv2c community without an ACL",
                          "The community string travels in cleartext; at least restrict which hosts may use it, or move to SNMPv3.",
                          ["ip access-list standard SNMP-MGMT", " permit <NMS-IP>", "snmp-server community <COMMUNITY> RO SNMP-MGMT",
                           "write memory"], [ln]))
    return out


@rule("ssh")
def r_ssh(c: Config, ctx: dict):
    out = []
    if not c.has(r"^ip ssh version 2$"):
        out.append(_f("ssh", "medium", "SSH version 2 not enforced",
                      "Without `ip ssh version 2` the router may still negotiate SSHv1 with old clients.",
                      ["ip ssh version 2", "write memory"]))
    # DH size and key-exchange come from `show ip ssh` (IOS hides defaults in the config, so the config alone can't tell).
    facts = (ctx.get("facts") or {}).get("ssh") or ""
    m = re.search(r"Minimum expected Diffie Hellman key size\s*:\s*(\d+)", facts)
    if m and int(m.group(1)) < 2048:
        out.append(_f("ssh", "low", f"SSH Diffie-Hellman minimum is {m.group(1)} bits",
                      "Allows a weak 1024-bit key exchange.",
                      ["crypto key generate rsa modulus 2048", "ip ssh dh min size 2048", "write memory"],
                      [f"show ip ssh: Minimum expected Diffie Hellman key size : {m.group(1)} bits"]))
    k = re.search(r"KEX Algorithms:\s*(.+)", facts)
    if k and not re.search(r"sha256|sha512|curve25519|ecdh", k.group(1)):
        out.append(_f("ssh", "low", "SSH key exchange offers SHA-1 methods only",
                      "This IOS only offers diffie-hellman-*-sha1 key exchange, which current SSH clients (OpenSSH 9+, paramiko 5+) "
                      "refuse by default. It is a limitation of the IOS image, not a setting: check whether stronger methods exist "
                      "with `ip ssh server algorithm kex ?`; if only sha1 is listed, the fix is an IOS upgrade or a newer router. "
                      "The monitor pins an SSH library that still accepts these methods.",
                      ["! check: ip ssh server algorithm kex ?", "! if a sha256 option exists:",
                       "ip ssh server algorithm kex diffie-hellman-group14-sha256", "write memory"],
                      [f"show ip ssh: KEX Algorithms: {k.group(1).strip()}"]))
    if not c.has(r"^login block-for"):
        out.append(_f("ssh", "low", "No login brute-force protection (login block-for)",
                      "Unlimited password guesses over SSH.",
                      ["login block-for 120 attempts 5 within 60", "login on-failure log", "write memory"]))
    return out


@rule("small_services")
def r_services(c: Config, ctx: dict):
    out = []
    checks = [
        (r"^service tcp-small-servers$", "medium", "TCP small servers enabled (echo/chargen/discard)", ["no service tcp-small-servers"]),
        (r"^service udp-small-servers$", "medium", "UDP small servers enabled", ["no service udp-small-servers"]),
        (r"^(ip finger|service finger)$", "medium", "Finger service enabled (user enumeration)", ["no ip finger"]),
        (r"^ip bootp server$", "low", "BOOTP server enabled", ["no ip bootp server"]),
        (r"^service pad$", "low", "X.25 PAD service enabled", ["no service pad"]),
        (r"^ip identd$", "low", "identd enabled", ["no ip identd"]),
    ]
    for pat, sev, title, fix in checks:
        ev = c.top(pat)
        if ev:
            out.append(_f("small_services", sev, title, "Legacy service with no business use on a WAN router; it only adds attack surface.",
                          fix + ["write memory"], ev))
    if not c.has(r"^no ip source-route$"):
        out.append(_f("small_services", "low", "IP source routing not disabled",
                      "Source-routed packets can be used to bypass path-based controls.", ["no ip source-route", "write memory"]))
    if c.has(r"^cdp run$") or (not c.has(r"^no cdp run$") and not c.has(r"^no cdp")):
        pass  # handled per WAN interface below
    return out


@rule("wan_interface")
def r_wan(c: Config, ctx: dict):
    out = []
    cdp_global_off = c.has(r"^no cdp run$")
    for h, b in c.wan_interfaces(ctx.get("wan_interfaces", [])).items():
        if not any(x.startswith("ip access-group") and x.endswith(" in") for x in b):
            out.append(_f("wan_interface", "high", f"{h}: no inbound ACL on the internet-facing interface",
                          "With no inbound ACL, every service the router runs (SSH, SNMP, HTTP...) is reachable from the modem side. "
                          "If the modem ever forwards traffic or is bridged, the router is exposed to the internet.",
                          ["! blocks management ports from the WAN side without touching NAT return traffic",
                           "ip access-list extended WAN-IN", " deny tcp any any eq 22 log", " deny tcp any any eq 23 log",
                           " deny tcp any any eq 80", " deny tcp any any eq 443", " deny udp any any eq 161",
                           " permit ip any any",
                           h, " ip access-group WAN-IN in", "write memory"], [h]))
        if not cdp_global_off and "no cdp enable" not in b:
            out.append(_f("wan_interface", "low", f"{h}: CDP enabled towards the modem/ISP",
                          "CDP advertises the router model, IOS version and addresses to whatever is on the other end.",
                          [h, " no cdp enable", "! or globally:", "no cdp run", "write memory"], [h]))
        for feat, cmd in (("ip redirects", "no ip redirects"), ("ip unreachables", "no ip unreachables"), ("ip proxy-arp", "no ip proxy-arp")):
            if cmd not in b:
                out.append(_f("wan_interface", "low", f"{h}: {feat} not disabled",
                              f"{feat} on the internet-facing interface helps attackers map the network or redirect traffic.",
                              [h, f" {cmd}", "write memory"], [h]))
        if "ip directed-broadcast" in b:
            out.append(_f("wan_interface", "medium", f"{h}: directed broadcasts enabled (smurf amplification)",
                          "Allows the router to be used as a broadcast amplifier.", [h, " no ip directed-broadcast", "write memory"], [h]))
    return out


@rule("logging_time")
def r_logging(c: Config, ctx: dict):
    out = []
    if not c.has(r"^logging (host|\d+\.\d+\.\d+\.\d+)"):
        out.append(_f("logging_time", "low", "No syslog server configured",
                      "Logs only live in the router's buffer and are lost on reboot - the first thing you need after an incident.",
                      ["logging host <SYSLOG-IP>", "logging trap informational", "logging buffered 64000", "write memory"]))
    if not c.has(r"^service timestamps log datetime"):
        out.append(_f("logging_time", "low", "Log timestamps not configured",
                      "Without timestamps, log lines cannot be correlated with outages.",
                      ["service timestamps log datetime msec localtime show-timezone", "service timestamps debug datetime msec", "write memory"]))
    if not c.has(r"^ntp (server|peer)"):
        out.append(_f("logging_time", "low", "No NTP server",
                      "Clock drift makes logs, certificates and the daily backups hard to trust.",
                      ["ntp server <NTP-IP-OR-pool.ntp.org>", "clock timezone <TZ> <OFFSET>", "write memory"]))
    return out


@rule("accounts")
def r_accounts(c: Config, ctx: dict):
    out = []
    users = c.top(r"^username\s+\S+")
    names = {re.match(r"username\s+(\S+)", u).group(1).lower() for u in users}
    monitor_user = (ctx.get("monitor_user") or "").lower()
    for weak in names & {"cisco", "admin", "administrator", "root", "user", "guest", "test"}:
        fix = ["username <PERSONAL-NAME> privilege 15 algorithm-type scrypt secret <NEW-STRONG-SECRET>"]
        if weak == monitor_user:
            fix += [f"! '{weak}' is the account THIS MONITOR logs in with. Before removing it:",
                    "!   1. create the new account above and test it from the monitor PC,",
                    "!   2. put it in .env (CISCO_USERNAME / CISCO_PASSWORD) and run: docker compose up -d --force-recreate",
                    "!   3. only then:"]
        fix += [f"no username {weak}", "write memory"]
        out.append(_f("accounts", "medium", f"Default-style account name '{weak}'",
                      "Well-known account names halve the work of a brute-force attack. Use a named account per person and "
                      "remove shared ones when staff leave." + (" This is also the monitor's own login - see the fix notes." if weak == monitor_user else ""),
                      fix, [u for u in users if u.lower().startswith(f"username {weak} ")]))
    if not c.has(r"^aaa new-model$"):
        out.append(_f("accounts", "low", "AAA not enabled (aaa new-model)",
                      "Per-user accounting and lockout policies need AAA; local login without it is acceptable for a small site.",
                      ["aaa new-model", "aaa authentication login default local", "aaa authorization exec default local", "write memory"]))
    if not c.has(r"^banner (motd|login)"):
        out.append(_f("accounts", "low", "No login banner",
                      "A legal 'authorised access only' banner is expected by most audits and supports prosecution.",
                      ["banner login ^C", "Unauthorised access prohibited. Activity is monitored.", "^C", "write memory"]))
    return out


# --------------------------------------------------------------------------- run
def audit_config(raw_config: str, device: str, wan_interfaces: Iterable[str] = ("GigabitEthernet0/0",),
                 monitor_user: str = "", facts: Optional[dict] = None) -> list[Finding]:
    """facts: optional read-only command output that the config alone cannot show, e.g. {"ssh": <show ip ssh>}."""
    c = Config(raw_config)
    ctx = {"wan_interfaces": list(wan_interfaces), "monitor_user": monitor_user, "facts": facts or {}}
    findings: list[Finding] = []
    for rid, fn in RULES:
        try:
            for f in fn(c, ctx):
                f.device = device
                findings.append(f)
        except Exception as e:  # noqa: BLE001 - a broken rule must not stop the audit
            findings.append(Finding("audit_error", "low", f"Rule {rid} failed", f"{type(e).__name__}: {e}", [], [], device))
    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.rule, f.title))
    return findings


def score(findings: list[Finding]) -> int:
    """0-100 posture score: 100 = clean. Critical -25, high -10, medium -4, low -1 (floor 0)."""
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
    return max(0, 100 - sum(weights.get(f.severity, 0) for f in findings))


def fix_script(findings: list[Finding], device: str) -> str:
    """Printable remediation script for one router (placeholders in <ANGLE-BRACKETS> must be filled in)."""
    lines = [f"! Remediation for {device} - review every line; replace <PLACEHOLDERS>; apply in a maintenance window",
             "! Keep a console/second session open while changing vty, ACL or SSH settings.", "configure terminal"]
    seen = set()
    for f in sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9)):
        block = tuple(x for x in f.fix if x != "write memory")
        if not block or block in seen:
            continue
        seen.add(block)
        lines.append(f"! [{f.severity.upper()}] {f.title}")
        lines.extend(block)
    lines += ["end", "write memory"]
    return "\n".join(lines)

# Rule Tuning Guide

A detection that fires constantly gets ignored, and an ignored detection is worse than no detection — it occupies the budget of a real one while providing nothing. This document records the expected false-positive behaviour of every rule in the repository and what to do about it.

Thresholds live in [`rules/threshold.config`](../rules/threshold.config) rather than inline in the rules, so tuning never requires editing match logic.

---

## Deployment order

Do not enable this ruleset in blocking mode, or even in alerting mode, on day one.

1. **Days 1–7 — observe.** Load the rules, send alerts to a log nobody pages on. Collect volume per SID.
2. **Day 7 — rank by volume.** Any SID producing more than a handful of alerts per day per host is a tuning target, regardless of how good the detection looks on paper.
3. **Days 7–14 — tune.** Apply thresholds, add suppressions for identified benign sources, adjust entropy values against your own baseline.
4. **Day 14 — promote.** Move the tuned set to a monitored queue. Only then consider IPS mode, and only for rules whose false-positive rate you have measured rather than estimated.

---

## Per-rule analysis

### Web application attacks

**SID 1000001 — SQL Injection: UNION SELECT**
Expected FPs: low. Genuine matches on `UNION` and `SELECT` within 30 bytes in a URI are rare outside attacks. Watch for: analytics and BI tools that pass query fragments in URLs, and security-training platforms.
Evasion note: this catches unobfuscated injection only. Comment insertion (`UNI/**/ON`), case mixing with encoding, and inline hex all defeat it. It is a tripwire for commodity scanners, not a WAF.

**SID 1000002 — Path Traversal**
Expected FPs: low-to-moderate. Some single-page applications produce `../` sequences in legitimate route fragments. If your application does this, suppress by destination rather than disabling.

**SID 1000003 — XSS: script tag in URI**
Expected FPs: moderate. Fires on security scanners, on WAF-testing tools, and occasionally on legitimate content-management previews. Severity is deliberately Minor.
Coverage note: URI-only. It does not inspect POST bodies, which is where most stored-XSS payloads arrive.

**SID 1000009 — LFI: /etc/passwd**
Expected FPs: very low. Few legitimate applications reference `/etc/passwd` in a URI. One of the highest-precision rules here.

### Authentication attacks

**SID 1000004 — SSH brute force**
Threshold: 5 attempts / 60s / source.
Rationale: a human mistyping produces two or three attempts. Automated guessing produces dozens. Five sits above human error and below meaningful attacker progress.
Expected FPs: moderate on networks with automation. CI runners, backup jobs, and configuration-management tools all reconnect frequently. Suppress by source IP for known automation rather than raising the count — raising it hides real attacks too.

**SID 1000012 — HTTP Basic Auth brute force**
Threshold: 10 / 60s / source, higher than SSH because some clients retry authentication automatically on page load.
Expected FPs: moderate. API clients with expired credentials retry aggressively.

### Reconnaissance

**SID 1000005 — Scanner tool User-Agent**
Expected FPs: depends entirely on whether you run authorised scanning. If you do, suppress by the scanner's source IP — see the commented example in `threshold.config`. Do not disable the rule; you want to know when scanning comes from somewhere unexpected.
Evasion note: trivially defeated by changing the user agent. Present because unsophisticated scanning is still common, not because it stops anyone competent.

**SID 1000013 — Excessive 404 responses**
Threshold: 20 / 60s / destination.
Expected FPs: high on sites with broken links, missing favicons, or aggressive crawlers. Severity is Informational for this reason. Consider raising the count substantially on public-facing sites.

### DNS and C2

**SID 1000006 — Low-reputation TLD**
**rev:2 tuning change.** `.xyz` and `.top` were removed from the pattern. Both now carry millions of legitimate registrations and were the dominant false-positive source. The remaining TLDs — `.tk`, `.ml`, `.ga`, `.cf`, `.gq` — are the Freenom-era free registrations with far lower legitimate volume.
Expected FPs after tuning: low, but non-zero. Severity is Informational; treat as an enrichment signal, not an alert.

**SID 1000014 — DNS query matching the malicious-domain dataset**
Expected FPs: as good as the feed. A stale blocklist produces both false positives (domains that changed hands) and false negatives.
Feed integration: replace `datasets/malicious-domains.txt` with output from your threat-intel platform. Remember the base64 requirement — see [`known-limitations.md`](known-limitations.md#2-type-string-datasets-are-base64-encoded-and-reject-comments):

```bash
# convert a plain-text domain list to Suricata dataset format
while read -r d; do printf '%s' "$d" | base64; done < feed.txt > malicious-domains.txt
```

**SID 1000015 — Long DNS query label (7.x)**
Expected FPs: moderate. CDN and cloud hostnames are legitimately long. Superseded by the entropy rules on Suricata 8; retained for 7.x sensors.

**SIDs 1000201–1000203 — Entropy-based DNS tunneling (Suricata 8)**

Entropy thresholds are **the most environment-sensitive parameter in this repository.** Suricata's `entropy` keyword computes Shannon entropy on a 0–8 scale.

| Content type | Typical entropy |
|---|---|
| English-like hostnames | 2.5 – 3.5 |
| CDN / cloud generated hostnames | 3.5 – 4.2 |
| Base32/base64 encoded payload | 4.2 – 5.0+ |

The overlap between generated hostnames and encoded payloads is real and unavoidable. The defaults here — 3.8 for the general rule, 4.2 for the sustained-volume rule — sit inside that overlap deliberately, favouring recall over precision on the assumption you will tune down.

**Baseline before enabling.** Capture a day of normal DNS, compute the entropy distribution of your own query names, and set the threshold above your 99th percentile. A threshold chosen from this table rather than from your own traffic will either flood you or miss the tunnel.

SID 1000201 is rate-limited to one alert per source per minute; without that limit a single tunneling session buries the console.

### Malware and post-exploitation

**SID 1000007 — Reverse shell in request body**
**rev:2 correction.** rev:1 inspected outbound traffic with no sticky buffer, matching raw payload in the wrong direction. A reverse-shell one-liner arrives *inbound* as a command-injection payload; the resulting shell session is not HTTP at all. Now anchored to `http.request_body` on inbound traffic.
Expected FPs: very low. Also expect low true-positive volume — this catches a specific unobfuscated payload shape.

**SID 1000008 — PowerShell download cradle User-Agent**
Expected FPs: moderate in Windows environments with legitimate PowerShell automation — software deployment, monitoring agents, update scripts. Suppress by source for known automation hosts.

**SID 1000016 — CLI downloader to raw-IP host**
**rev:2 tuning change, and the most significant one in this release.** rev:1 alerted on any `curl` or `wget` user agent. That fires on every `apt update`, every CI job, every container pull, and every package install — it was the highest-volume false positive in the ruleset by a wide margin.
rev:2 requires **both** a CLI user agent **and** a Host header that is a bare IPv4 address. Fetching from a raw IP with a command-line tool is the pattern actually associated with malware staging; fetching from a domain is ordinary system administration.
Expected FPs after tuning: low. Some internal artifact repositories are addressed by IP — suppress those by destination.

**SID 1000010 — Low-reputation source IP**
Expected FPs: as good as the reputation feed. The shipped `iprep/reputation.list` contains RFC 5737 documentation addresses only and will never match real traffic; replace it with a live feed.
Required `suricata.yaml` configuration:

```yaml
reputation-categories-file: /etc/suricata/iprep/categories.txt
default-reputation-path: /etc/suricata/iprep
reputation-files:
  - reputation.list
```

### Modern TLS

**SID 1000101 — JA4 on the offensive-tooling list**
Ships with an empty dataset by design. A stale fingerprint blocklist is worse than none, because it creates the impression of coverage. Populate from the [FoxIO JA4+ database](https://ja4db.com) or your own intel.
Expected FPs: very low once populated. JA4 collisions between malware and legitimate software do occur — verify a match before acting on it.

**SID 1000102 — Browser JA4 not on the post-quantum allowlist**
Expected FPs: **high until baselined.** This rule alerts on anything not in your allowlist, so an unpopulated allowlist means everything alerts.
Build the allowlist by collecting JA4 hashes from known-good managed endpoints across your standard browser builds, then add them. Re-baseline after each major browser release — a Chrome update changes the fingerprint.
Largest structural FP source: TLS-inspection proxies, which rewrite the Client Hello and produce their own fingerprint. Exclude proxy egress addresses.

**SID 1000103 — TLS Client Hello without SNI**
Expected FPs: rising over time, which is why severity is Informational and the rule is heavily rate-limited. See [`known-limitations.md`](known-limitations.md) and the companion Wireshark project for why this detection is weakening rather than improving.
Also fires on: legacy IoT devices with minimal TLS stacks, some VPN client bootstrap traffic.

**SIDs 1000104 / 1000105 — ECH without preceding DNS HTTPS-RR lookup**
Expected FPs: moderate, from three identified causes:
1. **DoH/DoQ** — the HTTPS-RR lookup is invisible, so the xbit never sets and every ECH session alerts. On DoH-heavy networks this rule is unusable without resolver-log correlation.
2. **DNS caching** — a lookup older than the 300s xbit window produces a false positive. Widen `expire` on networks with long TTLs.
3. **Session resumption** — reuses a previously obtained config.

Before enabling, confirm what fraction of your endpoints use encrypted DNS. If it is significant, treat this rule as a hunting query rather than an alert.

---

## Writing suppressions

Every suppression is a deliberate blind spot. Two rules make them safe:

**Scope narrowly.** Suppress by source or destination IP, never globally. `suppress gen_id 1, sig_id 1000005` disables the rule everywhere; `suppress gen_id 1, sig_id 1000005, track by_src, ip 10.20.30.40` disables it for one authorised scanner.

**Justify in a comment.** An undocumented suppression is indistinguishable from a blind spot six months later. Record what was suppressed, why, and who decided.

```
# Authorised DMZ vulnerability scanner (ticket SEC-1182, approved 2026-07-29).
# Review at next quarterly ruleset audit.
suppress gen_id 1, sig_id 1000005, track by_src, ip 10.20.30.40
```

---

## Measuring whether tuning worked

Track two numbers per SID, weekly:

- **Alert volume** — is it falling toward something an analyst can review?
- **Disposition ratio** — of the alerts reviewed, what fraction were true positives?

A rule with falling volume and a rising true-positive ratio is tuning correctly. Falling volume with an unchanged ratio means you are suppressing signal along with noise, and the threshold went too far.

The [`alert_summary.sh`](../scripts/alert_summary.sh) script produces the per-signature counts this measurement needs.

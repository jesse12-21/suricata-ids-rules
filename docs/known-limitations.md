# Known Limitations

Findings from compiling this ruleset against a real Suricata engine. Each entry records what was tested, what was observed, and what was done about it.

The premise of this document is that a rule you have not loaded into Suricata is a rule you have not written. Syntax that looks correct in an editor fails in the engine for reasons that are not obvious until you run it.

---

## 1. The previous ruleset did not load

**Affects:** `rules/local.rules` rev:1
**Found:** 2026-07-29
**Status:** fixed

Running the engine against the previous version of the ruleset produced:

```console
$ suricata -T -S rules/local.rules
E: detect: error parsing signature "alert dns $HOME_NET any -> any any
   (msg:"LOCAL DNS Query to Known Malicious Domain"; dns.query;
   dataset:isset,malicious_domains,type string,load malicious_domains.txt; ...)"
   from file rules/local.rules at line 61
E: suricata: Loading signatures failed.
```

SID 1000014 referenced `malicious_domains.txt`, which was not in the repository. Suricata resolves `load` at rule-parse time, so a missing dataset file does not skip that one rule — **it fails the entire ruleset**. Every other rule in the file was correct and none of them would have loaded.

Anyone cloning the repository and running the validation command in the README would have hit this immediately.

**Fixed** by shipping `datasets/malicious-domains.txt`, and by adding a CI job that compiles the ruleset on every push so this class of failure cannot recur.

---

## 2. `type string` datasets are base64-encoded, and reject comments

**Affects:** dataset file format
**Found:** 2026-07-29
**Status:** documented, files corrected

The first version of the shipped dataset used plain-text domains with explanatory `#` comments at the top. Suricata rejected it:

```console
E: datasets: bad base64 encoding malicious-domains/malicious-domains.txt
```

Two things are true that the format's name does not suggest:

- A `type string` dataset stores **base64-encoded** values, one per line — not plain strings.
- Comment lines are **not** tolerated. Every line is fed to the base64 decoder, so a `#` header fails the whole file.

This is why `datasets/*.txt` in this repository contain no comments and look opaque. To read or extend one:

```bash
# read
while read -r line; do echo "$line" | base64 -d; echo; done < datasets/malicious-domains.txt

# add an entry
printf '%s' 'newdomain.invalid' | base64 >> datasets/malicious-domains.txt
```

---

## 3. `iprep` rules fail to parse without a categories file

**Affects:** `rules/local.rules` SID 1000010
**Found:** 2026-07-29
**Status:** fixed

The previous ruleset carried SID 1000010 commented out, with a note saying it required `malicious_ips.txt` in the datasets directory. That note was wrong on two counts: `iprep` does not read from the datasets directory, and it does not use that format.

`iprep` requires a **reputation categories file** declaring named categories, and one or more **reputation list files** in `<ip>,<category-id>,<score>` format. Without the categories file, the category name in the rule is unknown and the rule fails to parse:

```console
E: detect-iprep: "src,BadHosts,>,50" is not a valid setting for iprep
```

**Fixed** by shipping `iprep/categories.txt` and `iprep/reputation.list`, enabling the rule, and documenting the required `suricata.yaml` stanza in [`tuning-guide.md`](tuning-guide.md). The addresses in the shipped list are RFC 5737 documentation ranges and cannot match live infrastructure.

---

## 4. The Ubuntu-packaged Suricata is built without JA4

**Affects:** all JA4 rules; sensor deployment generally
**Found:** 2026-07-29
**Status:** handled with `requires:`

The Suricata in the Ubuntu 24.04 repositories is 7.0.3, and its build does not include JA3/JA4 support:

```console
$ suricata --build-info | grep Features
Features: NFQ PCAP_SET_BUFF AF_PACKET HAVE_PACKET_FANOUT LIBCAP_NG LIBNET1.1
          HAVE_HTP_URI_NORMALIZE_HOOK PCRE_JIT HAVE_NSS HTTP2_DECOMPRESSION
          HAVE_LUA HAVE_LUAJIT HAVE_LIBJANSSON TLS TLS_C11 MAGIC RUST
```

A bare `ja4.hash` rule on such a build is a hard parse error, which — per finding 1 — takes the whole ruleset with it:

```console
E: detect: error parsing signature "... ja4.hash; content:"t13d1516h2"; ..."
```

Adding `requires: feature ja4;` changes the outcome from failure to a clean skip:

```console
i: requires: 2 rules were skipped because the running Suricata version
   does not have features: [ja4]
```

**This is why every JA4 rule in `rules/modern-tls.rules` is gated.** The same applies to Suricata 8 keywords (`entropy`, `absent`, `dns.rrtype`) via `requires: version >= 8.0;`. Verified behaviour on 7.0.3:

```console
i: requires: 6 rules were skipped because the running Suricata version
   7.0.3 is less than 8.0.0; 2 rules were skipped because the running
   Suricata version does not have features: [ja4]
i: suricata: Configuration provided was successfully loaded. Exiting.
```

The practical consequence: this ruleset can be dropped onto a 7.x sensor without breaking it. The modern detections simply do not arm. The CI installs Suricata 8 from the OISF stable PPA specifically so that the gated rules are actually exercised rather than silently skipped.

---

## 5. Thresholds warn when their rule file is not loaded

**Affects:** `rules/threshold.config`
**Status:** expected behaviour, noted

Validating a single rule file while `threshold.config` references SIDs in the other files produces:

```console
W: threshold-config: can't suppress sid 1000203, gid 1: unknown rule
```

These are warnings, not errors, and they disappear when the full ruleset is loaded together. The CI concatenates all rule files before validating for this reason. Worth knowing so the warning is not mistaken for a broken threshold.

---

## 6. Dataset `load` paths resolve against `default-rule-path`

**Affects:** any rule using `dataset:...load`; CI and deployment instructions
**Found:** 2026-07-29 (surfaced by a CI failure)
**Status:** fixed

Copying dataset files to `/var/lib/suricata/datasets/` — the conventional location, and the one most documentation implies — is **not** sufficient. Suricata resolves a bare `load` filename against `default-rule-path`, and falls back to the current working directory. It does not search the datasets directory.

Reproduced by running from a directory that does not contain the files, with the files correctly present in `/var/lib/suricata/datasets/`:

```console
$ suricata -T -S combined.rules
E: datasets: fopen 'malicious-domains.txt' failed: No such file or directory
E: detect-dataset: failed to set up dataset 'malicious-domains'.
E: detect: error parsing signature "... dataset:isset,malicious-domains,... " at line 84
```

Three resolutions were tested. Two work:

| Approach | Result |
|---|---|
| `--set default-rule-path=/var/lib/suricata/datasets` | works |
| Run Suricata with the dataset directory as the working directory | works |
| `--data-dir=/var/lib/suricata` | **fails** |

The first is used in CI and in the README validation instructions, because it does not depend on the working directory.

This is worth internalising beyond this repository: per finding 1, a dataset file Suricata cannot open fails the **entire ruleset**, not the one rule referencing it. A path assumption is therefore a whole-ruleset outage.

---

## 7. A `.gitignore` rule silently excluded files the ruleset depends on

**Affects:** `datasets/*`, and by cascade `iprep/*`
**Found:** 2026-07-29 (CI failure, second occurrence)
**Status:** fixed

The repository's `.gitignore` carried a sensible-looking rule:

```
# Threat intel datasets (may be downloaded)
datasets/*.txt
```

The intent was to avoid committing large downloaded threat feeds. The effect was that the small seed datasets the rules *depend on* were excluded from every commit. They existed locally, so local validation passed; they were absent from the checkout, so CI failed.

The failure presented misleadingly. CI reported:

```
E: reputation: opening ip rep file /etc/suricata/iprep/categories.txt: No such file or directory
E: detect-dataset: failed to set up dataset 'malicious-domains'.
E: detect-dataset: failed to set up dataset 'offensive-ja4'.
E: detect-iprep: "src,BadHosts,>,50" is not a valid setting for iprep
```

Four distinct-looking errors across three rule files, pointing at datasets, reputation, and rule syntax. All from one cause: the staging step ran `cp datasets/*.txt` first, the glob matched nothing, `cp` exited non-zero, and bash's `set -e` aborted the step before `cp iprep/*` ever ran. The reputation files were committed correctly and still never reached the runner.

**Fixed** two ways:

- `.gitignore` now negates the shipped seed files explicitly, keeping the exclusion for downloaded feeds:
  ```
  datasets/*.txt
  datasets/*.netset
  !datasets/malicious-domains.txt
  !datasets/pq-browser-ja4.txt
  !datasets/offensive-ja4.txt
  ```
- CI gained a **Verify required files are present** step that runs before staging and names any missing file directly, rather than letting the absence surface as downstream rule errors.

The general lesson, and the reason this is recorded rather than quietly patched: **a detection repository has runtime data dependencies, and version control must be configured to know the difference between data that is generated and data that is required.** An ignore rule written for one purpose silently broke another. Local validation could not catch it, because the files were present locally — only a clean checkout exposes it, which is precisely what CI is for.

---

## 8. Detection coverage gaps

Inherent to the detection approach rather than tooling defects. Each is also stated in the relevant rule.

| Gap | Affects | Detail |
|---|---|---|
| **Encrypted DNS** | SIDs 1000006, 1000014, 1000015, 1000201-1000203, 1000105 | DoH and DoQ carry DNS inside HTTPS. Suricata sees TLS, not queries. Every DNS rule here is blind on hosts using encrypted DNS; resolver-log correlation is required instead. |
| **ECH cover names** | SID 1000105 | Under ECH the visible SNI is the provider's public name. Destination-name detection is unavailable by design for that traffic. |
| **No supported_groups keyword** | SID 1000102 | Suricata cannot match the TLS supported_groups extension directly, so the post-quantum detection is expressed as a JA4 allowlist rather than "group != 4588". This requires environment-specific baselining to be useful. |
| **xbits window vs DNS TTL** | SIDs 1000104/1000105 | The 300s cross-flow correlation window can miss a cached HTTPS-RR lookup that happened earlier, producing a false positive. |
| **TLS inspection proxies** | SIDs 1000102, 1000103 | A proxy that terminates and re-originates TLS rewrites the Client Hello, changing JA4 and potentially stripping SNI. Exclude proxy egress addresses. |
| **Encrypted payloads** | SIDs 1000001-1000003, 1000007, 1000009 | All HTTP content rules require cleartext. They see nothing on HTTPS without TLS interception. |

---

*Findings recorded while compiling the ruleset against Suricata 7.0.3 RELEASE. CI validates against Suricata 8 from the OISF stable PPA.*

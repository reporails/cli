---
id: CORE:G:0013
slug: no-personal-data
title: No Personal Data
category: governance
type: deterministic
severity: medium
match: {format: [freeform, frontmatter, schema_validated], vcs: committed}
---

# No Personal Data

Instruction files must not contain personal data. Every agent session loads the file, and everyone who can read the repository sees it, so a real social security number, phone number, address or wallet committed there is exposed to all of them and stays in the git history.

The check reports every line that holds such a value, in prose and in code blocks, in the file you wrote and in any file it imports with `@path` (the finding names the imported file and its line). It reports:

- a US social security number: `123-45-6789`
- an international phone number: `+<country code>` followed by a separator and 8 to 15 digits in total, for example `+44 20 7946 0958`
- a MAC address: `3c:22:fb:12:34:56` or `3c-22-fb-12-34-56`
- a public IPv4 address, for example `52.14.200.3`, including one after `ssh user@` or inside a URL such as `http://52.10.20.30/`
- a personal email address, for example `jane.doe@gmail.com` or `ploi@corp.io` written in prose
- a Bitcoin wallet address (`bc1…`, or a `1…`/`3…` address) or an Ethereum wallet address (`0x` followed by 40 hex digits)

The check leaves placeholders and reserved values alone:

- SSNs with area number `000`, `666` or `9xx`, and a value made of one repeated digit
- the MAC addresses `00:00:00:00:00:00` and `ff:ff:ff:ff:ff:ff`
- private, loopback, link-local, shared-address and documentation IPv4 ranges (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `169.254.x`, `100.64-127.x`, `192.0.2.x`, `198.51.100.x`, `203.0.113.x`, `0.0.0.0`), netmasks, version strings with more than four parts, and the public DNS resolvers `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, `9.9.9.9` and `149.112.112.112`
- a four-part number read as a version: one right after `=`, `v`, `V` or `@` (`foo==1.2.3.4`, `v1.2.3.4`, `pkg@1.2.3.4`), or on a line that has `version` or `release` (any case) up to 200 characters earlier (`AssemblyVersion("1.0.0.0")`, `Version 2.3.4.5 released`); an `@` right before an address still counts as an SSH target, and is reported, when `ssh`, `scp`, `rsync`, `sftp` or `mosh` comes up to three words earlier
- email addresses at `example.com`, `example.org`, `example.net`, `test.com`, `*.example`, `*.test`, `*.invalid`, `*.local`, `users.noreply.github.com`, role addresses (`security@`, `support@`, `info@`, `contact@`, `hello@`, `admin@`, `abuse@`, `privacy@`, `team@`, `sales@`, `help@`, `billing@`, `legal@`, `press@`, `postmaster@`, `webmaster@`, `noreply@`, `no-reply@`, `bugs@`, `dev@`, `ops@`, `hr@`, `jobs@`, `careers@`) and addresses starting `user@`, `you@`, `name@`, `email@`, `someone@` or `git@` at any domain, an SSH or SCP target (`user@host` with `ssh`, `scp`, `rsync`, `sftp` or `mosh` up to three words earlier, or inside `ssh://`), and any value on a line whose key is `author`, `maintainer`, `email` or `contact` in frontmatter or JSON, because a declared contact is deliberate
- the Ethereum zero address, git SHAs, semantic versions, dates and UUIDs

## Antipatterns

- Writing `Ask Jane at jane.doe@gmail.com` in a support section -- the check reports the personal address.
- Pasting `ssh deploy@52.14.200.3` or a server's public address into setup steps -- the check reports the public IP.
- Listing a test device as `3c:22:fb:12:34:56` -- the check reports the MAC address.
- Importing a file with `@docs/contacts.md` that holds a phone number -- the check reports it in the imported file.

## Pass / Fail

### Pass

~~~~markdown
## Contacts

Support: support@corp.io, security@corp.io
Server: 192.168.1.10 (see docs/network.md)
DNS: 8.8.8.8 or 1.1.1.1; pin with `pip install foo==1.2.3.4`
Deploy: ssh deploy@build.corp.io
Test SSN: 000-12-3456
Device: 00:00:00:00:00:00
Commit: 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
~~~~

### Fail

~~~~markdown
## Contacts

Ask Jane at jane.doe@gmail.com or +44 20 7946 0958
Employee SSN: 123-45-6789
Production host: 52.14.200.3
~~~~

## Limitations

Does not detect credit card numbers: a regular expression cannot run the Luhn check, so a digit pattern alone would flag order numbers and IDs. Does not detect names, street addresses, dates of birth, national IDs other than the US SSN, phone numbers written without a leading `+`, or IPv6 addresses. A personal email on a line keyed `author`, `maintainer`, `email` or `contact` is treated as a declared contact and is not reported; a list under `authors:` is reported. A public IPv4 address is reported even when it is a well-known service outside the six listed resolvers, and a bare four-part version such as `1.2.3.4` with none of the version cues above is read as an address. An `@` before an address with no `ssh`-style command nearby is read as a package version (`pkg@1.2.3.4`), so `root@203.45.67.89` on its own line is not reported. The word `version` or `release` anywhere in the 200 characters before an address, including inside `Released`, clears it, so a real address on such a line is missed. Role addresses are never reported, even when they belong to a person. A personal address after `ssh`, `scp`, `rsync`, `sftp` or `mosh` and up to three words is read as an SSH target, so `ssh into the box then mail jane@gmail.com` is missed while a longer gap is reported. The `author` and `contact` line guard looks back 200 characters. The `1…`/`3…` Bitcoin form is matched only for 26 to 35 character tokens that mix upper case, lower case and at least two digits, to avoid flagging hashes and identifiers, so some real addresses are missed and a rare identifier can be reported. Does not validate wallet checksums.

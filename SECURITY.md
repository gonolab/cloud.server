# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue, pull request or discussion.

Use GitHub's private vulnerability reporting: open
[Report a vulnerability](https://github.com/gonolab/cloud.server/security/advisories/new) on
the repository's **Security** tab. The report stays visible only to you and the maintainers, and
the discussion, the fix and the advisory happen in the same place.

A useful report says:

- which component and version are affected (`gono-cloud --version`, or the commit);
- what an attacker can do, and what they need for it (network access only, an app password, a
  web login, access to the server);
- how to reproduce it: requests, configuration, client;
- whether you have seen it exploited.

The maintainers confirm the problem in the advisory, work on a fix, publish a release and then
the advisory, crediting you unless you prefer otherwise. Please keep the details private until
the advisory is published.

## Supported versions

| Component | Supported |
|---|---|
| Server, latest `server-v*` release | Yes |
| Server, older releases | Upgrade to the latest release; fixes are not backported |
| Legacy implementation (`v0.1.x` tags) | No |

## Scope

In scope: the server (`crates/server/`), its release archives, the install script and the
service files (`packaging/server/`), and the release workflow.

Problems in a dependency are welcome too. If the problem is in dav-server, which this
repository vendors with a patch (`vendor/dav-server/`), report it to the
[dav-server-rs project](https://github.com/messense/dav-server-rs) as well. Problems in the
Nextcloud clients belong to the [Nextcloud projects](https://github.com/nextcloud).

The deployment model is part of the security design: the server listens on loopback behind a
reverse proxy that terminates TLS (`docs/reverse-proxy.md`), and it runs as a dedicated service
user with a sandboxed systemd unit (`docs/deployment.md`). Reports that need a different setup,
for example the server exposed directly to the internet without TLS, are still welcome, but say
so.

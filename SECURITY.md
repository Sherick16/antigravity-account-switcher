# Security Policy

## Reporting a Vulnerability

Please report security issues privately through [GitHub Security Advisories](https://github.com/Sherick16/antigravity-account-switcher/security/advisories/new). Include the affected commit, operating system, Go version, reproduction steps, and any relevant logs with tokens or personal data removed.

This fork is maintained independently from the upstream project. Do not disclose credentials, OAuth codes, refresh tokens, or the contents of `accounts.db` in an issue or pull request.

## Local service boundary

The dashboard and proxy bind to loopback (`127.0.0.1`) by default. `serve --bind` rejects non-loopback addresses unless `--unsafe-bind` is supplied explicitly. An unsafe bind exposes the local control plane and proxy to the selected network; use it only behind a trusted network boundary.

The HTTP server validates local `Host` values and rejects cross-site `Sec-Fetch-Site` requests. Requests carrying an `Origin` header must use a permitted local origin for dashboard and API routes. State-changing `/api/*` routes and both OAuth-start routes are covered. Explicit Antigravity reverse-proxy and forward-proxy traffic remains supported; proxy requests are identified by CONNECT, absolute-form targets, or Cloud Code request shapes and do not use an upstream Google `Host` as a dashboard origin.

OAuth account onboarding uses a short-lived loopback callback listener on `127.0.0.1`, PKCE, and a state value. The callback validates and consumes the state before exchanging the authorization code.

## Credential and database storage

The SQLite database contains access tokens, refresh tokens, and account metadata. It is treated as a credential store:

- the configuration directory is created or repaired to mode `0700`;
- the database file is created or repaired to mode `0600`;
- existing unsafe permissions are repaired at startup;
- SQLite WAL and SHM sidecars remain protected by the private `0700` parent directory.

The database is not encrypted at rest. Protect the user account, home directory, backups, and any copied database files. Configuration files are also written with mode `0600`.

## OAuth client credentials

The application may use credentials discovered from the local Antigravity installation or supplied through `ANTIGRAVITY_CLIENT_ID` and `ANTIGRAVITY_CLIENT_SECRET`. Treat those values and all OAuth tokens as sensitive. Native-app OAuth client credentials are not a substitute for protecting the local credential store.

## Scope and limitations

The service is intended for a trusted local user. The `--unsafe-bind` override is an explicit operator decision to widen that boundary. The application does not provide encryption for the SQLite file, multi-user authorization, or a replacement for host-level firewall and account protections.

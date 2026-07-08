# Test Plan

Keep this document current: when a command or behavior is added or changed,
update the matching checklist here.

## Automated suite

- [ ] `uv run pytest` — all tests pass, output pristine (no warnings/errors)
  - Covers: provider presets, token store persistence and permissions,
    logging service, HTTPS callback server (real TLS via trustme), client
    token exchange/refresh against a real local endpoint, the client
    credentials grant (fetch, auto-renewal, CLI), mkcert certificate
    generation, and the non-interactive CLI commands.

## CLI walkthrough

Prerequisites: `uv sync` done; mkcert installed and `mkcert -install` run.

### oauth2 providers

- [ ] `uv run oauth2 providers` prints `brightspace`, `generic`, `google`,
      `microsoft` and exits 0.

### oauth2 authorize

- [ ] `uv run oauth2 authorize` with no flags exits non-zero and shows usage.
- [ ] Real provider run (use any one provider you have credentials for):
      `uv run oauth2 authorize --provider google --client-id ... --client-secret ... --scopes "openid email" --name testToken --extra-auth-param access_type=offline --extra-auth-param prompt=consent`
  - [ ] First run generates `working/certs/localhost.pem` and logs the event.
  - [ ] Browser opens the provider consent page automatically.
  - [ ] After approving, the browser shows "Authorization complete".
  - [ ] CLI prints `Token 'testToken' saved.` with an expiry and exits 0.
  - [ ] `working/tokens/testToken.json` exists with permissions `-rw-------`.
  - [ ] `working/logs/oauth2.log` contains the INFO events for the run.
- [ ] `--no-browser` prints the authorization URL instead of opening a browser.
- [ ] Denying consent at the provider makes the CLI exit 1 with the
      provider's error (e.g. `access_denied`) printed and logged as ERROR.
- [ ] `--timeout 5` with no browser action exits 1 with a timeout error.
- [ ] `--provider generic` without `--auth-url`/`--token-url` exits 1 with a
      clear error.
- [ ] `--provider microsoft --tenant <tenant>` sends you to that tenant's
      login page.

### oauth2 authorize --manual (headless)

Run these over SSH or in a terminal, treating it as a machine with no browser.

- [ ] `uv run oauth2 authorize --manual --provider <provider> ...` prints the
      authorization URL and instructions, then waits at a paste prompt —
      without opening a browser and without generating `working/certs/`.
- [ ] Opening the URL on another device and approving lands the browser on
      `https://localhost:8400/callback` with a connection error; the address
      bar contains `code=` and `state=`.
- [ ] Pasting that full URL at the prompt prints `Token '<name>' saved.`
      with an expiry and exits 0; the token appears in `working/tokens/`.
- [ ] Pasting a URL whose `state` was tampered with exits 1 with a state
      mismatch error and saves nothing.
- [ ] Pasting an empty line exits 1 with an error saying nothing was entered.
- [ ] Works with mkcert not installed on the machine.

### oauth2 authorize --client-credentials (service-to-service, no user)

Use a Microsoft or Brightspace app registration set up for the client
credentials grant (Google is not supported for this grant).

- [ ] `uv run oauth2 authorize --client-credentials --provider microsoft --tenant <tenant> --client-id ... --client-secret ... --scopes "https://graph.microsoft.com/.default" --name serviceToken`
      prints `Token 'serviceToken' saved.` with an expiry and exits 0 —
      without opening a browser and without generating `working/certs/`.
- [ ] Same with `--provider brightspace` and a Brightspace registration that
      has the client credentials grant enabled.
- [ ] `uv run oauth2 status --name serviceToken` shows
      `Grant: client_credentials` and `Refresh token: absent`.
- [ ] `uv run oauth2 refresh --name serviceToken` renews the token by
      re-running the grant and exits 0.
- [ ] A wrong client secret exits 1 with the provider's error printed and
      logged as ERROR.
- [ ] `--provider generic` works with only `--token-url` (no `--auth-url`
      required).

### oauth2 status

- [ ] `uv run oauth2 status --name testToken` shows provider, scopes,
      `Refresh token: present`, and `valid until <timestamp>`; exits 0.
- [ ] After the access token expires, status shows `expired at <timestamp>`.
- [ ] `uv run oauth2 status --name doesNotExist` exits 1 with an error on
      stderr.

### oauth2 refresh

- [ ] `uv run oauth2 refresh --name testToken` prints
      `Token 'testToken' refreshed.` with a new expiry and exits 0.
- [ ] `working/logs/oauth2.log` gains a `token 'testToken' refreshed` INFO event.
- [ ] `uv run oauth2 refresh --name doesNotExist` exits 1 with an error.
- [ ] After rotating the client secret at the provider, refresh exits 1 with
      `invalid_client` plus the hint that the secret may have been rotated
      or expired.

### oauth2 list

- [ ] `uv run oauth2 list` shows `testToken`; exits 0.
- [ ] With an empty working dir (`--working-dir /tmp/emptydir`), prints
      `No tokens saved yet.` and exits 0.

### oauth2 delete

- [ ] `uv run oauth2 delete --name testToken` prints
      `Token 'testToken' deleted.` and removes the file; exits 0.
- [ ] Running it again exits 1 with an error on stderr.

## Library usage

- [ ] In a separate project, `from simpleoauth2token import OAuth2Client` works
      and `getAccessToken()` returns the saved token without a browser.
- [ ] With an expired access token and valid refresh token,
      `getAccessToken()` refreshes transparently and returns a new token.
- [ ] With no saved token, `getAccessToken()` raises `OAuth2Error` telling
      you to run authorize.
- [ ] With `grantType="client_credentials"` and no saved token,
      `getAccessToken()` obtains a token on its own — no manual step, no
      browser — and renews it after expiry the same way.
- [ ] `getAccessToken(forceRefresh=True)` renews a token that has not
      expired yet (use after an API answers 401 for a revoked token).

# Publishing simpleoauth2token to PyPI

Steps to build and publish this library to [PyPI](https://pypi.org). We use
[uv](https://docs.astral.sh/uv/) for building and publishing — no twine or
setuptools needed.

## One-time setup

1. Create an account at [pypi.org](https://pypi.org/account/register/).
   Two-factor authentication is mandatory for new accounts.
2. Create an API token: **Account Settings → API tokens → Add API token**.
   - The **first** publish of a new project requires an **account-scoped**
     token (project-scoped tokens can only be created for projects that
     already exist on PyPI).
   - After the first release, create a token scoped to just
     `simpleoauth2token` and delete the account-scoped one.
3. Store the token somewhere safe (a password manager). It is shown only
   once, and it uploads under the username `__token__`.

## Pre-publish checklist

- [ ] Bump `version` in [pyproject.toml](pyproject.toml) — PyPI rejects
      re-uploads of an existing version, so every publish needs a new one.
- [ ] Tests pass: `uv run pytest`
- [ ] No type errors: `uvx pyright --pythonpath .venv/bin/python src tests`
- [ ] README is accurate — it is the package's PyPI landing page.
- [ ] [TESTPLAN.md](TESTPLAN.md) reflects any command changes.
- [ ] Changes are committed and pushed.

## Build

```bash
rm -rf dist
uv build
```

This produces `dist/simpleoauth2token-<version>.tar.gz` (sdist) and
`dist/simpleoauth2token-<version>-py3-none-any.whl` (wheel).

Sanity-check the artifacts before uploading:

```bash
# LICENSE must appear in both (requires license-files in pyproject.toml)
tar -tzf dist/simpleoauth2token-*.tar.gz | grep LICENSE
unzip -l dist/simpleoauth2token-*-py3-none-any.whl | grep LICENSE

# The wheel installs and works in a clean venv
uv venv /tmp/wheeltest
uv pip install --python /tmp/wheeltest/bin/python dist/simpleoauth2token-*.whl
/tmp/wheeltest/bin/simpleoauth2token providers
rm -rf /tmp/wheeltest
```

## Publish

```bash
uv publish --token pypi-YOUR-TOKEN-HERE
```

Alternatively set the token in the environment so it stays out of shell
history:

```bash
export UV_PUBLISH_TOKEN=pypi-YOUR-TOKEN-HERE
uv publish
```

## Verify the live package

```bash
uv run --no-project --with simpleoauth2token -- \
  python -c "import simpleoauth2token; print('ok')"
```

Then check the listing renders correctly at
<https://pypi.org/project/simpleoauth2token/>.

## Dry run against TestPyPI (optional but recommended for risky releases)

TestPyPI is a separate instance with its own account and tokens
([test.pypi.org](https://test.pypi.org)):

```bash
uv publish --publish-url https://test.pypi.org/legacy/ --token pypi-TESTPYPI-TOKEN
```

Install from it to verify (the extra `--index` lets dependencies resolve
from real PyPI):

```bash
uv run --no-project \
  --index https://test.pypi.org/simple/ \
  --index https://pypi.org/simple/ \
  --with simpleoauth2token -- python -c "import simpleoauth2token; print('ok')"
```

## Things to know

- **Releases are immutable.** You cannot fix or replace an uploaded
  version. If a release is broken, *yank* it on PyPI (hides it from
  resolvers while keeping existing pins working) and publish a patch
  version.
- **The version must change every publish.** Even a README-only fix needs
  a version bump.
- The console script claims the name `simpleoauth2token` on the user's
  PATH; the package was named to avoid Google's deprecated `oauth2client`.
- **Future improvement:** PyPI *trusted publishing* lets a GitHub Actions
  workflow publish on tagged releases via OIDC — no long-lived token to
  store. Worth setting up once releases become regular.

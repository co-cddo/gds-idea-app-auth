# PyPI Index Implementation Plan

## Goal

Create a private, GitHub Pages-hosted PyPI index that serves all internal `co-cddo` packages, enabling standard version ranges (`>=0.2.0`) instead of git URL pinning. Leverages GitHub Enterprise's ability to restrict Pages access to organisation members.

---

## Architecture

```
Consumer (pip/uv)
    |
    | https://co-cddo.github.io/pypi-index/simple/
    | (restricted to co-cddo org members)
    v
co-cddo/pypi-index (private repo, GitHub Pages)
    |
    | /simple/index.html          -- lists all packages
    | /simple/cognito-auth/       -- links to wheels
    | /simple/gds-idea-app-kit/   -- links to wheels
    | /simple/gds-idea-cdk-.../   -- links to wheels
    | /packages/*.whl             -- actual wheel files
    |
    v
Wheels downloaded from GitHub Release assets at build time
    - co-cddo/gds-idea-app-auth     (public)
    - co-cddo/gds-idea-app-kit      (public)
    - co-cddo/gds-idea-cdk-constructs (private)
```

Key design decisions:
- Wheels are **copied into the index repo's Pages site**, not linked to release assets. This avoids double-authentication issues (Pages auth + Release asset auth).
- The index is a **private repo** with Pages restricted to org members.
- One index URL for all packages -- consumers don't need to know which are public/private.

---

## New Repository: `co-cddo/pypi-index`

### File Structure

```
co-cddo/pypi-index/
├── .github/
│   └── workflows/
│       └── rebuild.yml          # GitHub Action to rebuild and deploy index
├── packages.json                # Config: which repos to index
├── build_index.py               # Script to generate the PEP 503 index
├── requirements.txt             # Dependencies for build script (if any)
└── README.md                    # Documentation for maintainers
```

The `site/` directory is generated at build time and deployed to Pages. It is never committed.

### packages.json

```json
{
  "repos": [
    {
      "repo": "co-cddo/gds-idea-app-auth",
      "package_name": "cognito-auth"
    },
    {
      "repo": "co-cddo/gds-idea-app-kit",
      "package_name": "gds-idea-app-kit"
    },
    {
      "repo": "co-cddo/gds-idea-cdk-constructs",
      "package_name": "gds-idea-cdk-constructs"
    }
  ]
}
```

### build_index.py

A Python script (~100 lines, no external dependencies beyond `requests` or using `gh` CLI) that:

1. Reads `packages.json`
2. For each repo, calls `gh api repos/{repo}/releases` to list all releases
3. For each release, downloads `.whl` and `.tar.gz` assets into `site/packages/`
4. Generates `site/simple/index.html`:
   ```html
   <!DOCTYPE html>
   <html><body>
     <a href="cognito-auth/">cognito-auth</a>
     <a href="gds-idea-app-kit/">gds-idea-app-kit</a>
     <a href="gds-idea-cdk-constructs/">gds-idea-cdk-constructs</a>
   </body></html>
   ```
5. For each package, generates `site/simple/{package-name}/index.html`:
   ```html
   <!DOCTYPE html>
   <html><body>
     <a href="../../packages/cognito_auth-0.2.3-py3-none-any.whl">
       cognito_auth-0.2.3-py3-none-any.whl
     </a>
     <a href="../../packages/cognito_auth-0.2.2-py3-none-any.whl">
       cognito_auth-0.2.2-py3-none-any.whl
     </a>
   </body></html>
   ```

This follows the PEP 503 Simple Repository API that pip/uv understand natively.

### .github/workflows/rebuild.yml

```yaml
name: Rebuild PyPI Index

on:
  workflow_dispatch:       # Manual trigger
  repository_dispatch:     # Triggered by package repos on release
    types: [package-released]

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Build index
        run: python build_index.py
        env:
          GH_TOKEN: ${{ secrets.PACKAGE_READER_TOKEN }}

      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: site/

      - name: Deploy to GitHub Pages
        uses: actions/deploy-pages@v4
```

`PACKAGE_READER_TOKEN` is a fine-grained PAT with `contents:read` on all three package repos (needed to download release assets from the private repo).

---

## Changes to Package Repos

### 1. co-cddo/gds-idea-app-auth (release.yml)

Add after the "Create GitHub Release" step:

```yaml
      - name: Trigger PyPI index rebuild
        if: steps.check_tag.outputs.exists == 'false'
        run: |
          gh api repos/co-cddo/pypi-index/dispatches \
            -f event_type=package-released
        env:
          GH_TOKEN: ${{ secrets.PYPI_INDEX_TRIGGER_TOKEN }}
```

### 2. co-cddo/gds-idea-app-kit (release.yml)

Same addition as above.

### 3. co-cddo/gds-idea-cdk-constructs (release.yml)

Same addition as above. If this repo doesn't have a release workflow that builds wheels and attaches them to releases, one needs to be created following the same pattern as `gds-idea-app-auth`.

---

## Changes to Consumer Configuration

### gds-idea-app-kit templates

Update `pyproject.toml.template` for each framework:

**Before:**
```toml
dependencies = [
    "cognito-auth[streamlit] @ git+https://github.com/co-cddo/gds-idea-app-auth.git",
]
```

**After:**
```toml
[tool.uv]
extra-index-url = ["https://co-cddo.github.io/pypi-index/simple/"]

[project]
dependencies = [
    "cognito-auth[streamlit]>=0.2.0",
]
```

### Dev container setup

Add to the dev container's post-create or post-start command:

```bash
# Authenticate pip/uv with GitHub Pages (for private index)
echo "machine co-cddo.github.io
login x-access-token
password ${GITHUB_TOKEN}" >> ~/.netrc
chmod 600 ~/.netrc
```

The `GITHUB_TOKEN` is already available in GitHub Codespaces and can be injected into local dev containers via `gds-idea-app-kit`.

### CI (GitHub Actions)

In CI workflows that run `uv sync` or `pip install`, add:

```yaml
      - name: Configure private index auth
        run: |
          echo "machine co-cddo.github.io
          login x-access-token
          password ${{ secrets.GITHUB_TOKEN }}" >> ~/.netrc
```

`secrets.GITHUB_TOKEN` is automatically available in Actions and has read access to org-level Pages sites.

---

## GitHub Tokens Required

| Token | Purpose | Scope | Stored where |
|---|---|---|---|
| `PACKAGE_READER_TOKEN` | Index rebuild workflow downloads release assets (including from private repos) | `contents:read` on all 3 package repos | `co-cddo/pypi-index` repo secret |
| `PYPI_INDEX_TRIGGER_TOKEN` | Package repos trigger index rebuild on release | `actions:write` on `co-cddo/pypi-index` | Secret in each package repo |
| `GITHUB_TOKEN` (automatic) | Consumers authenticate against private Pages site | Automatic in Actions/Codespaces | N/A (built-in) |

Recommended: Use a **GitHub App** instead of PATs for `PACKAGE_READER_TOKEN` and `PYPI_INDEX_TRIGGER_TOKEN`. This avoids tokens being tied to a personal account and provides better audit logging. A single GitHub App installed on the org can have the necessary permissions.

---

## Changes to cognito-auth Documentation

### README.md

Update install section:

```bash
# Configure the private index (one-time setup)
# See: https://github.com/co-cddo/pypi-index

# Then install normally:
pip install "cognito-auth[streamlit]>=0.2.0" \
    --extra-index-url https://co-cddo.github.io/pypi-index/simple/
```

### docs/index.md

Update the Installation section similarly. Add a note that `gds-idea-app-kit` projects come pre-configured.

---

## GitHub Pages Configuration

After creating the `co-cddo/pypi-index` repo:

1. Go to Settings > Pages
2. Source: GitHub Actions
3. Go to Settings > Pages > Access
4. Set to: "Only members of co-cddo" (Enterprise feature)

This ensures only authenticated org members can access the index and download wheels.

---

## Execution Steps (in order)

### Phase 1: Create the index (30 min)

1. Create `co-cddo/pypi-index` as a **private** repo
2. Add `packages.json`, `build_index.py`, `.github/workflows/rebuild.yml`
3. Create the `PACKAGE_READER_TOKEN` (fine-grained PAT or GitHub App)
4. Add it as a repo secret on `pypi-index`
5. Enable GitHub Pages (source: Actions, access: org members only)
6. Run the workflow manually to seed the initial index
7. Verify: visit `https://co-cddo.github.io/pypi-index/simple/` while logged in

### Phase 2: Test the index (15 min)

8. From a local machine (with `~/.netrc` configured):
   ```bash
   pip install "cognito-auth[streamlit]>=0.2.0" \
       --extra-index-url https://co-cddo.github.io/pypi-index/simple/
   ```
9. Verify version resolution works (`>=0.2.0` installs latest)
10. Test with `uv add` as well

### Phase 3: Wire up automatic rebuilds (15 min)

11. Create the `PYPI_INDEX_TRIGGER_TOKEN` (PAT or GitHub App)
12. Add as secret to `gds-idea-app-auth`, `gds-idea-app-kit`, `gds-idea-cdk-constructs`
13. Update release workflows in all three repos to trigger index rebuild
14. Test: push a release, verify index updates automatically

### Phase 4: Update consumers (30 min)

15. Update `gds-idea-app-kit` templates (`pyproject.toml.template`, dev container config)
16. Update `gds-idea-app-auth` docs (README.md, docs/index.md)
17. Update any existing projects to use the new index URL

---

## Estimated Total Effort

| Phase | Time |
|---|---|
| Create the index repo + script + workflow | 30 min |
| Test end-to-end | 15 min |
| Wire up automatic rebuilds | 15 min |
| Update consumer templates and docs | 30 min |
| **Total** | **~1.5 hours** |

---

## Future Considerations

- **Adding a new package**: Add an entry to `packages.json`, ensure the repo has a release workflow that attaches wheels, add the `PYPI_INDEX_TRIGGER_TOKEN` secret, and re-run the index rebuild.
- **Removing a package**: Remove from `packages.json` and re-run. Old wheels will no longer be served.
- **SHA256 hashes**: For extra security, `build_index.py` can include `#sha256=...` fragments on download links (PEP 503 compliant). pip will verify wheel integrity. Worth adding.
- **Migration path to public PyPI**: If you ever want to publish `cognito-auth` to public PyPI, the version numbers and wheel format are already compatible. Just add a `twine upload` step.

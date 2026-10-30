# TRACEE Quickstart

This guide runs the current TRACEE dashboard and API locally from a fresh
checkout. It uses a new vault path; do not point it at an existing case or
vault. The server binds only to `127.0.0.1`. Do not expose this development
server to a public or shared network.

## 1. Check out and install

Use Python 3.10 or newer. Replace `YOUR_TRACEE_REPOSITORY_URL` below with the
repository URL supplied to you.

```sh
git clone YOUR_TRACEE_REPOSITORY_URL TRACEE
cd TRACEE
python -m venv .venv
```

Activate the virtual environment:

```sh
# Linux or macOS
. .venv/bin/activate
```

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install runtime and test dependencies:

```sh
python -m pip install -e ".[test]"
```

On Windows, install the optional collector dependency if you intend to use the
Windows Event Log collector:

```powershell
python -m pip install -e ".[windows]"
```

## 2. Configure a new local vault and API credential

Choose a new vault directory in your user data area. The examples below use a
dedicated `tracee-quickstart` directory. The initialization call creates the
required vault structure. There is no `tracee init` command.

### Linux or macOS

```sh
export TRACEE_API_VAULT_DIR="$HOME/.local/share/tracee-quickstart/vault"
export TRACEE_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export TRACEE_UPLOAD_TOKEN="$TRACEE_API_TOKEN"
python -c 'import os; from tracee.vault import FilesystemVaultStore; FilesystemVaultStore(os.environ["TRACEE_API_VAULT_DIR"]).initialize()'
```

### Windows PowerShell

```powershell
$env:TRACEE_API_VAULT_DIR = Join-Path $env:LOCALAPPDATA "TRACEE\quickstart\vault"
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$env:TRACEE_API_TOKEN = [Convert]::ToBase64String($bytes)
$env:TRACEE_UPLOAD_TOKEN = $env:TRACEE_API_TOKEN
$bytes = $null
$rng.Dispose()
python -c "import os; from tracee.vault import FilesystemVaultStore; FilesystemVaultStore(os.environ['TRACEE_API_VAULT_DIR']).initialize()"
```

These commands do not print the credential. Keep it out of URLs, screenshots,
logs, source files, and browser storage. Configure the environment before
starting the API; the vault path is selected when the application is created.
The API token is required for all `/api/v1` routes. Upload requires
`TRACEE_UPLOAD_TOKEN` to match it.

## 3. Start the local application

From the repository root, run:

```sh
python -m uvicorn tracee.api:app --app-dir src --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/> in a browser on the same machine. `/health` is
public and returns a liveness response; it does not prove the vault is
available. Enter the configured API credential when the UI prompts for it.
The UI keeps the credential in page memory. Locking the session clears that
page-held copy but does not revoke or rotate the server's shared credential.

The API documentation and OpenAPI endpoints are disabled by default. Do not
change the bind address to `0.0.0.0` or forward the port for this quickstart.

## 4. Use the application

The UI works with actual API and vault data. You can upload a selected evidence
file, inspect persisted metadata, run integrity verification, analyze supported
event formats, inspect event timeline provenance, and generate rule-based
reconstruction candidates from stored analysis. Candidate results do not prove
an attack, incident, causation, or independent corroboration. Relationship
data and findings/report generation are unavailable unless a future API
implements them.

For a complete repeatable walkthrough using synthetic JSONL evidence, follow
the [Windows hackathon demo runbook](hackathon-demo-runbook.md). It creates a
separate temporary vault and fixture rather than using this quickstart vault.

## 5. Run tests and stop

From the repository root:

```sh
python -m pytest -q
```

Optional UI source checks, when Node.js is available:

```sh
node --check ui/app.js
node --test tests/test_reconstruction_presentation.test.js
```

Stop Uvicorn with Ctrl+C. The quickstart vault remains at the configured
`TRACEE_API_VAULT_DIR`; preserve or back it up if it contains evidence you need.
Do not remove the directory blindly. To discard a disposable vault, first
verify that its path is the new quickstart path you created.

## Private and public deployment

This quickstart is for one local operator only. A private VM deployment should
keep Uvicorn bound to loopback and use a private-network-only gateway with
explicit access controls, a durable protected vault, and tested backup and
restore procedures. See [API Operations](API_OPERATIONS.md) for configuration
details. The current shared bearer token does not provide individual identity
or role-based authorization. TRACEE is not ready for public deployment; public
access requires a separate identity, authorization, transport, storage, and
operational security design.

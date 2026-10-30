# TRACEE Synthetic Hackathon Demo Runbook

This runbook demonstrates the current local UI and API using synthetic JSONL only. It creates a new, uniquely named vault and fixture under the current user's temporary directory. Do not point the demo at an existing vault. Keep the demo bound to `127.0.0.1`; never expose this development server to a public or shared network.

## Prerequisites

- Windows PowerShell and Python 3.10 or newer, with this checkout's dependencies available to that Python interpreter.
- A browser on the same computer.
- The repository checkout at `D:\CyberForensics\TRACEE` (or adjust the `Set-Location` command below to the actual checkout path).

From the repository root, install the project and test dependencies if they are not already installed:

```powershell
Set-Location D:\CyberForensics\TRACEE
python -m pip install -e ".[test]"
```

The development server command is the documented project command. It binds to the loopback interface only. Keep the API in the foreground terminal for this demo. Do not change the host to `0.0.0.0`, forward the port, or otherwise expose it to a public or shared network.

## Create an isolated demo vault and fixture

Use a dedicated PowerShell session for the demo and close it when finished. The setup below also snapshots the process-scoped TRACEE variables without displaying their values, so cleanup can restore pre-existing settings if you choose to reuse a session. Do not run commands that print these variables. Setup creates a fresh temporary directory, initializes the vault through the existing `FilesystemVaultStore` interface, generates one disposable random API credential in the shell environment, configures the upload compatibility token to the same value, and writes a UTF-8 JSONL fixture without a byte-order mark.

```powershell
Set-Location D:\CyberForensics\TRACEE

$demoEnvironmentNames = @(
  "TRACEE_API_TOKEN",
  "TRACEE_UPLOAD_TOKEN",
  "TRACEE_API_VAULT_DIR",
  "TRACEE_API_DOCS_ENABLED"
)
$demoPreviousEnvironment = @{}
$processEnvironment = [Environment]::GetEnvironmentVariables("Process")
foreach ($name in $demoEnvironmentNames) {
  $demoPreviousEnvironment[$name] = @{
    WasSet = $processEnvironment.Contains($name)
    Value = $processEnvironment[$name]
  }
}
$processEnvironment = $null
Remove-Item Env:TRACEE_API_DOCS_ENABLED -ErrorAction SilentlyContinue

$demoRoot = Join-Path $env:TEMP ("tracee-hackathon-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $demoRoot | Out-Null
$env:TRACEE_API_VAULT_DIR = Join-Path $demoRoot "vault"

$tokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($tokenBytes)
$demoToken = [Convert]::ToBase64String($tokenBytes)
$env:TRACEE_API_TOKEN = $demoToken
$env:TRACEE_UPLOAD_TOKEN = $demoToken
$demoToken = $null
$tokenBytes = $null
$rng.Dispose()

python -c "import sys; sys.path.insert(0, 'src'); from tracee.vault import FilesystemVaultStore; import os; FilesystemVaultStore(os.environ['TRACEE_API_VAULT_DIR']).initialize()"

$fixturePath = Join-Path $demoRoot "synthetic-login-events.jsonl"
$fixtureContent = @'
{"timestamp":"2026-10-18T10:00:00Z","event_type":"login","attributes":{"user":"demo-user"}}
{"timestamp":"2026-10-18T10:02:00Z","event_type":"login","attributes":{"user":"demo-user"}}
'@
[System.IO.File]::WriteAllText($fixturePath, $fixtureContent.TrimEnd() + "`n", [System.Text.UTF8Encoding]::new($false))
```

The `json_event` parser accepts one JSON object per line with `timestamp` and `event_type`; `attributes` may be a JSON object. The two records use valid UTC timestamps, the same synthetic user and event type, and are two minutes apart. The built-in `same-user-event-json_event` rule requires at least two matching observations with known timestamps within the candidate window. The UI's default window is 300 seconds, so this fixture is designed to produce one candidate hypothesis under the current rule.

The API credential is generated for this demo only and is not written into the repository or vault. The commands assign it without printing it. The UI prompts for it on page load; transfer it through the clipboard steps below without putting it in a URL, browser storage, screenshot, or log. The UI retains it only in page memory until you lock or close the page. This shared credential is not an investigator identity.

To enter it without printing it in the terminal, copy it to the clipboard only immediately before authorizing, then clear the clipboard:

```powershell
Set-Clipboard -Value $env:TRACEE_API_TOKEN
```

After pasting into the password field:

```powershell
Set-Clipboard -Value ""
```

## Start TRACEE

In the same PowerShell window, start the app from the repository root:

```powershell
python -m uvicorn tracee.api:app --app-dir src --host 127.0.0.1 --port 8000
```

The process remains in the foreground. Open `http://127.0.0.1:8000/` in the local browser. Do not start a second API against the same demo vault.
The API documentation endpoints are disabled by default. For local development only, optionally set `$env:TRACEE_API_DOCS_ENABLED = "1"` before starting the server to enable `/docs`, `/redoc`, and `/openapi.json`; unset it for the demonstration unless you need the schema.

## Browser walkthrough

Follow the workflow in this order. Evidence IDs and run IDs are generated by TRACEE; use the values shown by the UI rather than assuming any particular identifier.

1. **Confirm API and vault status.** On Dashboard, wait for the initial check. The header reports `API connected` only when `/health` returns the expected TRACEE health response; otherwise it reports `API unavailable`. The separate vault status should report `Vault available`, and the inventory should contain zero evidence records.

2. **Upload the synthetic fixture.** Authorize the page with the demo API credential when prompted. Open Evidence Explorer, choose **Add Evidence**, select `synthetic-login-events.jsonl` from the generated `$demoRoot`, and upload. The dialog should show **Evidence acquired** with the actual evidence ID, filename, size, SHA-256, and chain sequence. It also states that verification has not yet run. The upload route requires both configured token variables to contain the same value and continues to enforce its size and origin checks.

3. **Verify integrity.** Open Integrity Verification, select the new record, and choose **Run verification**. For this fresh demo vault, the expected state is `VALID`. The API checks the stored evidence payload, metadata binding, and complete evidence chain. A successful API response is accompanied by an activity-history entry for the verification.

4. **Run JSON event analysis.** Open **Event Analysis & Reconstruction**, select the new evidence record, choose **JSON event records** as the parser, and select **Run analysis**. The summary should report two parsed events and the uploaded evidence digest. Select that stored analysis and choose **Load selected analysis** to inspect both normalized events and their source observations. The observations should link to the uploaded evidence and source lines `line:1` and `line:2`.

5. **Run and inspect reconstruction.** With the analysis loaded, leave **Candidate window (seconds)** at `300` and select **Run reconstruction for selected analysis**. The UI displays the persisted summary and loads its detail. For the supplied fixture, expect `candidates_generated` with one hypothesis and two supporting observations. The card shows the backend interpretation, rule/version, input and supporting observation IDs, assumptions, unresolved conditions, limitations, and that the observations come from one evidence record. The backend's `corroborated` label means the rule's support threshold passed; it does not establish independent corroboration, malicious intent, identity, an incident, or causation.

6. **Inspect the timeline and provenance.** Open **Timeline & Relationships**, select the same evidence and stored analysis, then choose **Load timeline**. The two events should appear with their bounded UTC times. Select an event to inspect the source observation, evidence ID, source locator, parser, and raw timestamp details. Timeline order is temporal only. The UI explicitly states that relationship data is unavailable and that time order does not imply a causal link or incident.

7. **Review activity history.** Open **Investigation Activity** and select **Refresh activity** if needed. The newest-first list should include the actual acquisition, verification, analysis, and reconstruction operations and their recorded outcomes. Actor identity is not individually authenticated; entries show actor categories and do not prove which named person performed an action.

8. **Lock the UI session.** Select **Lock API session** in the header. The page reloads and clears its in-memory credential; the UI should return to its authorization prompt. This only clears the credential held by this page. It does not revoke or rotate the server's shared API credential.

9. **Confirm public health and protected inventory behavior.** With the API still running and API authentication configured, run these requests from PowerShell without an Authorization header:

```powershell
curl.exe --silent --show-error http://127.0.0.1:8000/health
curl.exe --silent --show-error -o NUL -w "HTTP %{http_code}" http://127.0.0.1:8000/api/v1/evidence
```

The health request should return `{"service":"TRACEE","status":"ok"}` without a token. The evidence request should report `HTTP 401`. If API authentication is not configured, the protected request instead returns `503`; configure the API credential before using this check.

## Troubleshooting

- **API unavailable:** Check the foreground terminal for startup errors and confirm the browser is using `http://127.0.0.1:8000/`. The UI health indicator and vault indicator are separate; API health alone does not establish vault availability.
- **API authorization rejected:** `api_auth_not_configured` or `api_auth_misconfigured` means the API token is absent or shorter than 32 characters; restart after setting `TRACEE_API_TOKEN`. `unauthorized` means the page credential does not match this server process. Lock the page and re-authorize with the value held in the PowerShell session.
- **Upload rejected:** `upload_disabled` means `TRACEE_UPLOAD_TOKEN` is absent. `upload_token_misconfigured` means it is weak or does not exactly match `TRACEE_API_TOKEN`. Both must be at least 32 characters and match; restart after changing configuration. A duplicate-content response means the file is already in this vault; do not retry it or switch to an existing vault for this demo.
- **Verification failed:** A result other than `VALID` means the current vault did not pass the reported integrity check. Stop the walkthrough and preserve the demo directory for inspection; do not edit or re-upload the stored object to force a passing result.
- **No reconstruction candidate:** Confirm the selected stored analysis used `json_event`, parsed both records, and shows the two matching user/event values and valid bounded UTC times. Confirm the candidate window is at least 120 seconds. If the API returns no candidate despite those conditions, record the actual response and stop rather than presenting a fabricated hypothesis.

## Generated data and safe shutdown

All intended demo data is beneath the unique `$demoRoot` printed by PowerShell's path variables if you inspect them. The fixture is `synthetic-login-events.jsonl`. The vault contains the initialized vault files and, during the walkthrough, the uploaded object, metadata, evidence chain, activity log, stored analysis, and stored reconstruction. The API also uses a temporary upload spool file and removes it after processing.

Stop the foreground server with **Ctrl+C**. After it exits, clear the clipboard copy of the demo credential, then restore the original process-scoped TRACEE environment values from the in-memory snapshot. Previously set values are restored without displaying them; variables that were absent before setup are removed. If the snapshot is unavailable, do not blindly remove variables because they may have existed before the demo.

```powershell
Set-Clipboard -Value ""
foreach ($name in $demoEnvironmentNames) {
    $previous = $demoPreviousEnvironment[$name]
    if ($previous.WasSet) {
        [Environment]::SetEnvironmentVariable($name, [string]$previous.Value, "Process")
    } else {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}
$demoPreviousEnvironment = $null
```

To remove the generated demo files, first verify `$demoRoot` is the unique `tracee-hackathon-...` directory under `$env:TEMP`, then run this guarded cleanup in the same PowerShell session:

```powershell
$tempPrefix = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
$demoPath = [System.IO.Path]::GetFullPath($demoRoot)
if ($demoPath.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and
    (Split-Path -Leaf $demoPath) -like 'tracee-hackathon-*') {
    Remove-Item -LiteralPath $demoPath -Recurse
} else {
    throw "Refusing cleanup: path is not the generated TRACEE demo directory under TEMP."
}
```

If the path cannot be verified, leave the directory in place. These commands never target the repository, its existing vaults, benchmarks, or other project data.

## Scope of this demonstration

The workflow demonstrates actual local API acquisition, integrity verification, parsing, rule-based candidate reconstruction, timeline provenance, and activity recording. It does not validate browser behavior in automation, individual investigator identity, independent-source corroboration, causal relationships, incident attribution, company-hosted security, or Windows Event Log collection.

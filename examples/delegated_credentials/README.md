# Delegated Credentials Demo — Short-lived STS creds + OIDC/Workload Identity + Confused-Deputy Prevention

> **⚠️ THIS IS A MOCKED DEMO. IT DOES NOT USE LIVE AWS.**
> Every AWS STS call in this directory is intercepted by
> [`moto`](https://github.com/getmoto/moto) via `@mock_aws`. **No real AWS
> account, credentials, IAM roles, or network calls are involved.** This is an
> additive, educational illustration of a pattern the linter recommends — it is
> **not** a hardened production control and it does **not** change any of the
> repo's existing static-linter claims or the README headline.

## Why this exists (Gap 3)

The static linter in this repo flags IAM anti-patterns. This demo shows the
*positive* pattern an AI agent should follow at runtime:

| Anti-pattern (BAD) | Delegated pattern (GOOD) |
|---|---|
| Ship a long-lived static access key inside the agent | Agent holds **no** permanent secret |
| Key never expires; huge blast radius if leaked | Creds are **short-lived** (e.g. 15 min) and scoped |
| Any deputy with the key acts as the agent | **`ExternalId`** blocks the *confused-deputy* attack |

The flow demonstrated:

```
OIDC / workload-identity token   (GitHub Actions OIDC, EKS IRSA, K8s SA token)
            │
            ▼
STS AssumeRoleWithWebIdentity  +  ExternalId condition   (confused-deputy guard)
            │
            ▼
SHORT-LIVED, SCOPED temporary credentials  (AccessKeyId + SessionToken + Expiration)
```

## Files

| File | Purpose |
|---|---|
| `delegated_credentials.py` | The MOCKED demo: `assume_role_for_agent()` exchanges an OIDC token for short-lived creds via `AssumeRoleWithWebIdentity`; `build_web_identity_trust_policy()` shows the trust policy with the `sts:ExternalId` condition; `static_key_antipattern()` shows the bad path for contrast. |
| `test_delegated_credentials.py` | `pytest` + `moto` (`@mock_aws`) tests proving (a) valid OIDC + correct ExternalId → scoped temp creds with expiry, (b) missing/wrong ExternalId → AccessDenied (confused deputy prevented), (c) creds are short-lived (`DurationSeconds` respected). |
| `README.md` | This file. |

## Confused-deputy prevention

A *confused deputy* is a privileged component tricked into misusing its
authority on behalf of an attacker. AWS's mitigation is the
[`ExternalId`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
secret, enforced by a trust-policy `Condition`:

```json
"Condition": { "StringEquals": { "sts:ExternalId": "agent-tenant-7f3a-external-id" } }
```

In real AWS, STS rejects an assume-role request that lacks the matching
`ExternalId` with **`AccessDenied`**. `moto` is lenient about enforcing
trust-policy conditions, so to make the control **demonstrable and
deterministic** the demo also validates the `ExternalId` in
`assume_role_for_agent()` and raises `ConfusedDeputyError` (AccessDenied
semantics). Both the portable client-side guard and the authoritative
server-side trust-policy condition are shown in the code.

## How to verify (reproduce it yourself)

This demo needs `moto` and `boto3`. A local `.venv-demo` is fine:

```powershell
# Windows PowerShell, from the repo root
C:\Users\pooja\AppData\Local\Programs\Python\Python312\python.exe -m venv .venv-demo
.\.venv-demo\Scripts\python.exe -m pip install --upgrade pip
.\.venv-demo\Scripts\python.exe -m pip install "moto[sts]" boto3 pytest

# Run the tests (all MOCKED — no real AWS)
.\.venv-demo\Scripts\python.exe -m pytest examples/delegated_credentials/test_delegated_credentials.py -v

# Optional: run the narrated MOCKED demo
.\.venv-demo\Scripts\python.exe examples/delegated_credentials/delegated_credentials.py
```

```bash
# macOS / Linux
python3.12 -m venv .venv-demo
./.venv-demo/bin/python -m pip install "moto[sts]" boto3 pytest
./.venv-demo/bin/python -m pytest examples/delegated_credentials/test_delegated_credentials.py -v
```

### Expected result

```
collected 6 items
examples/delegated_credentials/test_delegated_credentials.py ......   [100%]
6 passed
```

The six tests are:
- `test_valid_oidc_and_external_id_returns_scoped_temp_creds` — (a)
- `test_wrong_external_id_denied_confused_deputy_prevented` — (b)
- `test_missing_external_id_denied_confused_deputy_prevented` — (b)
- `test_credentials_are_short_lived_duration_respected` — (c)
- `test_longer_duration_produces_later_expiry_than_short_duration` — (c, monotonicity)
- `test_trust_policy_pins_oidc_subject_audience_and_external_id` — trust-policy shape

## What this demo is NOT

- **Not** live AWS. Nothing here authenticates to a real account.
- **Not** a production credential broker. No token signature verification,
  no caching/refresh, no error taxonomy beyond the demo.
- **Not** a change to the linter's rules or claims. It is purely additive.

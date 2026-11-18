# Mocked delegated-credentials teaching example

**MOCKED ONLY — not a production OIDC or credential-broker implementation.** The accompanying tests use moto and injected fake STS behavior. They do not authenticate a real token, access an AWS account, prove IAM authorization or establish real server-side trust enforcement. The studio does not run this example.

## What the code actually illustrates

`delegated_credentials.py` builds a trust-shaped dictionary, compares `provided_external_id` with `expected_external_id` locally, then calls a moto-backed `AssumeRoleWithWebIdentity` client to obtain credential-shaped values and expiration. The separate `static_key_antipattern()` returns clearly fake teaching values. `test_delegated_credentials.py` contains six cases covering the local comparison, mocked expiration and emitted dictionary shape.

The local comparison is **not** equivalent to an AWS trust-policy boundary: a caller can bypass a client-side check. Moto's acceptance of a policy/request shape does not validate its real STS semantics. In particular, **`AssumeRoleWithWebIdentity` has no ExternalId request parameter**. The helper's emitted `sts:ExternalId` condition and comments must not be used as a deployable web-identity trust policy. This documentation correction does not modify the example's runtime/tests or turn those tests into live validation.

Real patterns must be kept separate:

- OIDC/workload federation uses an approved provider, audience/subject claims and the appropriate web-identity API/trust policy.
- Third-party account-principal `AssumeRole` can use a properly reviewed ExternalId condition and parameter. ExternalId is a deputy/customer discriminator, not a universal secret or substitute for authentication.
- Temporary credential lifetime, refresh/revocation, permission scope and service authorization need their own actual validation. Merely having a session token does not prove least privilege.

See [AWS architecture](../../docs/aws-architecture.md) and [security controls](../../docs/aws-security-controls.md). Do not deploy the generated helper dictionary unchanged or invoke the helper against a real STS client to validate it.

## Reproduce the mocked checks

From the reviewed repository, using an isolated environment with pytest, boto3 and moto already installed (or approved test tooling):

```sh
python -m pytest examples/delegated_credentials/test_delegated_credentials.py -v
```

The explicit example-directory command matters: the normal configured test path is `tests`, so a main-suite count does not automatically include these six cases. Existing test names include “confused deputy prevented”; interpret them as local guard/mock observations only. Preserve exact source, dependency versions and actual outcomes before reporting a result; no current-head pass is asserted by an expected-output block.

The optional narrated `_demo()` prints **mock-generated credential-shaped values**. Prefer the tests and avoid publishing those values/logs as proof of a real credential exchange. No new API/provider key, paid service, account or role is required for the mocked tests. Live deployment/security review, token signature validation, authorization, broker isolation and credential lifecycle remain NOT IMPLEMENTED/NOT VERIFIED here.

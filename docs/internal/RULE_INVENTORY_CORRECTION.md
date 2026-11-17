# Rule inventory clarification

The baseline counted the static scanner correctly (24 IDs), but the whole product has a twenty-fifth ID in its live-context path. `src/aws_agent_identity_guard/live_scanner.py:435` emits `AIG-PB001` when a role with high/critical findings has no attached boundary. `tests/test_live_scanner.py:202` explicitly documents that this rule is not emitted by the static scanner.

The keyless browser static workflow must advertise 24 static rules and identify the additional live-context boundary-presence rule separately. It must not claim that an attached boundary proves effective restriction. Existing descriptions claiming 25 static rules need correction; the product-wide rule inventory is 25. No AWS API was called to establish this source-code finding.

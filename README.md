# make-trifecta-linter

Zero-dependency Python static analyzer for Make.com JSON blueprints. Traces untrusted-input-to-egress mapping paths across LLM nodes (OWASP LLM01 / Confused Deputy) and flags native LLM connectors that bypass enterprise AI Gateways.

## Threat Model
Low-code automations frequently wire public inputs (webhooks, web forms) into LLM nodes with outbound actions (Gmail, Slack, HTTP). System-prompt prohibitions ("never disclose internal data") are probabilistic and fail under adversarial input. Security boundaries must be enforced deterministically outside the model.

## Static Analysis vs. Empirical Validation
| Artifact | Method | What It Proves |
| :--- | :--- | :--- |
| `make_trifecta_linter.py` | Static blueprint analysis (SAST) | Identifies candidate variable mapping paths from untrusted ingress through an LLM to external egress, plus direct-to-provider AI Gateway bypasses. |
| Lab Note (PDF) | Controlled lab PoC (Runtime) | Demonstrates probabilistic confidentiality failure in a live Make.com workflow (identical Base64 payload leaking a synthetic `$50,000` field inside a refusal email in Run 1 vs. blocking in Run 2). |

## How It Works
1. **Graph Traversal:** Parses Make.com `flow` structures into a directed module graph.
2. **Module Classification:** Maps Make module identifiers into `UNTRUSTED_INPUT`, `LLM_NODE`, and `OUTBOUND_EGRESS`.
3. **Mapping-Reference Analysis:** Recursively inspects module `mapper` fields for variable references (`{{<module_id>.<field>}}`) to identify candidate data flow rather than naive node co-occurrence.
4. **AI Gateway Visibility:** Flags native SaaS LLM nodes (`openai-gpt-3:*`, `anthropic:*`) that may bypass corporate gateways, and HTTP nodes that call direct provider endpoints.

## Quick Start
```bash
python3 make_trifecta_linter.py samples/vulnerable_flow.json
python3 make_trifecta_linter.py samples/vulnerable_flow.json --gateway-host gateway.corp.internal
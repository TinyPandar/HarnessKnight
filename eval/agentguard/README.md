# AgentGuard detector evaluations

Run from the repository root with `python eval/agentguard/run_bypass_matrix.py` and `python eval/agentguard/run_public_injection.py`. Both use checked-in sample data and run offline. `fetch_public_injection.py` is optional and fetches network data only when explicitly run. These measure advisory rule behavior, not agent-level attack success.

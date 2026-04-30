---
skill_name: troubleshooting
display_name: Troubleshooting
category: diagnostics
risk_level: low
tools:
  - doctor
  - release_readiness
  - nmap_check
  - credentials_add_guidance
  - plugin_validate
triggers:
  - missing credentials
  - llm disabled
  - doc fetch disabled
  - nmap missing
  - preflight warning
  - plugin schema failure
requires_confirmation: []
forbidden:
  - bypassing_safety
---

# Troubleshooting Skill

Use this skill for common blockers: missing credentials, LLM disabled, documentation fetch disabled, Nmap missing, preflight warnings, and plugin schema failures. Explain the next safe command without bypassing policy.

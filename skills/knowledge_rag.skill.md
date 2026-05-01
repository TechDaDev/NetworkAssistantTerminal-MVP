---
skill_name: knowledge_rag
display_name: Knowledge and RAG
description: Use this skill when the user wants to search, list, show, or fetch documentation into local knowledge so the assistant can answer based on saved references without uncontrolled browsing.
category: knowledge
risk_level: low
tools:
  - knowledge_search
  - knowledge_list
  - knowledge_show
  - knowledge_add_guidance
  - knowledge_fetch_url
triggers:
  - knowledge search
  - show knowledge
  - fetch docs
requires_confirmation:
  - knowledge_fetch_url
forbidden:
  - automatic_browsing
---

# Knowledge and RAG Skill

Use local knowledge search/list/show for stored documentation. Fetching docs is explicit only and gated by settings. Normal `ask` does not browse automatically.

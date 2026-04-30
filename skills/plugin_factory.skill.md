---
skill_name: plugin_factory
display_name: Plugin Factory
category: plugin
risk_level: medium
tools:
  - plugin_generate
  - plugin_list
  - plugin_show
  - plugin_validate
  - plugin_approve
  - plugin_disable
  - plugin_run
triggers:
  - create a reusable tool
  - make a parser
  - build a planner plugin
  - add a new tool
requires_confirmation:
  - plugin_generate
  - plugin_approve
  - plugin_run
forbidden:
  - normal_operational_task_fallback
  - ssh_or_subprocess_plugins
---

# Plugin Factory Skill

Use plugin generation only for reusable planner, parser, validator, reporter, or diagnostic plugins. Do not use it for normal router connection, scanning, diagnostics, or configuration tasks when existing tools or custom plans fit.

Generated plugins start pending, must pass validation, and require approval before use. Forbidden imports/calls block validation. Planner plugin output can become a governed ChangePlan.

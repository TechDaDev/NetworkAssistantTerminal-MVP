---
skill_name: snapshots_backup
display_name: Snapshots and Backup
description: Use this skill when the user wants pre-change backups, snapshot listing and export, or deterministic restore guidance to protect rollback safety without automatically applying restore commands.
category: snapshot
risk_level: medium
tools:
  - snapshot_capture
  - snapshot_list
  - snapshot_show
  - snapshot_export
  - snapshot_restore_guidance
triggers:
  - backup router
  - backup config
  - save current config before change
  - show previous backup
  - restore guidance
requires_confirmation:
  - snapshot_capture
forbidden:
  - automatic_restore
---

# Snapshots and Backup Skill

Capture read-only snapshots before changes, list/show/export snapshots, and provide deterministic restore guidance. Restore guidance is informational only and never performs automatic restore.

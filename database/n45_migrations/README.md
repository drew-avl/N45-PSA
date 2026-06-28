# N45 database migrations

Add N45-specific SQL migrations here.

Filename format:

```text
YYYYMMDD_NNN_description.sql
```

Example:

```text
20260627_001_add_integration_events.sql
```

Rules:

1. Migrations must be safe to run once.
2. Never edit an applied migration.
3. Add a new corrective migration if a change is required.
4. Avoid destructive schema changes in the same release that removes old application code.
5. Test upgrades from a recent production backup in staging.

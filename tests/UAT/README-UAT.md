# Aurora UAT Suites

This directory contains reproducible User Acceptance Test labs for Aurora.

UAT suites are intentionally kept outside the product documentation. They are executable validation
environments for realistic access-review scenarios and should not introduce provider-specific
concepts into the Aurora core model.

Available suites:

- `CrashTests-CRM`: generic RBAC validation using a fictitious CRM for NexaByte IT.

Run a suite from the repository root:

```bash
tests/UAT/CrashTests-CRM/Run_CrashTests-CRM.sh
```

Remote execution example:

```bash
ssh vm-integrations \
  'cd ~/Aurora && tests/UAT/CrashTests-CRM/Run_CrashTests-CRM.sh'
```

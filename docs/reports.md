# Reports

Le rapport principal est `campaign-report.html`, autonome et filtrable. Il regroupe par defaut:

```text
Owner -> Service -> Access -> Identities
```

Les exports complementaires sont `campaign-results.csv`, `campaign-results.json`, `remediation.csv`
et `golden-source-diff.csv`.

Authentication data is rendered before access analysis when it is present in report metadata. Supported safe policy fields include authentication method, password status/policy, MFA requirement and methods, SSO/federation, token policy, session policy and local authentication. Missing values are shown as `Not collected`; raw credentials, passwords, tokens and keys are excluded from the HTML payload.

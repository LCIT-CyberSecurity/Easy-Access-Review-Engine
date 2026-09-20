# Campaign authorization and review scope

EARE keeps three separate boundaries:

- **Role**: what an EARE user can do.
- **Authorized domains** (`system_users.scopes`): the providers where that role can act.
- **Campaign review scope** (`Campaign.scope`): the expected/observed Access assignments selected for review.

An `ADMIN` is global. An `OPERATOR` can manage a campaign only when every provider exposed by its comparison rows is authorized. A row exposes both its Access provider and Identity provider; campaigns are allowed whole or denied whole, never silently truncated. `GROUP_OWNER` remains limited to assigned ReviewItems, and `BUSINESS_ADMIN` remains limited to provider-scoped remediation.

For example, Paul has role `OPERATOR` and authorized domains `ad-france`. A Sage campaign selecting `ad-france/GG_SAGE_RW` and `ad-france/GG_SAGE_RO` is within his domain. A Europe campaign spanning `ad-france` and `ad-germany` is not. A selected Access from `crm` whose comparison row contains an Identity from `openldap-corp` also requires authorization for both providers.

Campaign review scopes support:

```json
{"type":"all"}
{"type":"providers","values":["ad-france"]}
{"type":"accesses","values":[{"provider":"ad-france","name":"GG_SAGE_RW"}]}
```

Access references use the existing business key `(provider, name)`. The `accesses` scope is applied to all comparison classifications, including missing assignments found in Golden; unknown references are rejected rather than materialized as fake Access objects. Collection completeness remains a separate property of the Snapshot and is not an authorization or campaign-selection scope.

Campaign preview and opening use the same selection preparation. Authorization is enforced by the API for list, detail, lifecycle, review, and report endpoints; filtering happens server-side, and mixed-domain campaign details are not partially disclosed.

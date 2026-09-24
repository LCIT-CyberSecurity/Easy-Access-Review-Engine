# EARE Guide

EARE Guide is a deterministic, read-only assistant that explains the next useful step for the authenticated user. It combines the current role, authorized provider/campaign scope, current route, and factual EARE state. It is guidance, not authorization.

## Architecture

`GET /api/guidance?route=/current/path` authenticates the current session and builds a scope-filtered context from the existing repository projections. `access_review_engine.guidance` applies small deterministic rules and returns recommendations, readiness facts, and local page help. The WebUI renders that structure in the global Guide drawer and the first-login introduction.

The client cannot supply a role or obtain unfiltered data. The route is presentation context only. Recommendation links are emitted only when the authenticated user can use the corresponding EARE screen; campaign details are limited by the existing campaign authorization rules.

## Role journeys

- **ADMIN**: configure sources, collect an initial Snapshot, establish the expected state, then hand campaign governance to an Operator when one exists. Campaign preparation remains an allowed secondary path.
- **OPERATOR**: verify collection and expected state, prepare campaigns, continue authorized open campaigns, and inspect findings.
- **GROUP_OWNER**: see only assigned review workload and decide assigned access reviews.
- **BUSINESS_ADMIN**: see operational remediation actions in authorized domains.
- **REMEDIATION_MANAGER**: track and follow up remediation actions in authorized domains. EARE records the outcome; it does not modify LDAP, AD, cloud, or application systems.

## Onboarding and preferences

The default presentation mode is Standard: one lightweight introduction is shown once per authenticated subject and the Guide remains available from the header. Users can skip the introduction or disable the Guide. The presentation preference and onboarding dismissal are stored locally in the browser; workflow state is never persisted because it is derived from EARE data.

## Contextual help

The Guide contains local deterministic help for Overview, Sources, Golden Source, Campaigns, My Reviews, Actions, and Reports. The help consistently distinguishes observed source data, manual EARE enrichment, and Golden/expected state. No external documentation, Internet access, LLM, or free-text chatbot is used.

## No automatic actions

EARE Guide never synchronizes a source, creates or changes a Golden Source, approves or revokes a review, opens or closes a campaign, creates a user, or marks remediation complete. It only explains state and navigates to the normal screen where the user must review and explicitly confirm an operation.

## Future Ask EARE

The `GuidanceContext` and structured recommendation response are the factual boundary for a future Ask EARE layer. A future LLM may explain this authorized structure, but it must not become the source of truth or bypass the existing API authorization and business workflows.

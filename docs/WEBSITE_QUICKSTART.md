# Website assessment from a URL

1. Open New assessment and paste the full Target URL.
2. Click **Use website-only checks**. This clears source/ZIP and optional scanner/workflow selections.
3. Select **Internet access · No AI** for a public website.
4. Enter **Authorization reference**, for example your owner approval or engagement ticket.
5. Click **Prepare scope from URL**. Review the URL prefix and resolved IP addresses.
   Preparation performs DNS lookup only. It does not prove ownership, fetch the site or start a scan.
   A path URL keeps that path prefix; it is not widened to the whole origin.
6. Add excluded routes (such as logout) if needed. Check authorization and start.
   Changed DNS still blocks the scan until you review new pins.

The findings table groups equivalent built-in HTTP observations on the same origin.
Expand the affected-URL list and open each original finding for its evidence and review.
Groups do not establish a shared root cause. JSON/PDF exports and review IDs remain
per observation; source and cookie findings are not grouped by this view.

## Optional AI

Enable the dashboard with --experimental-ai. Select an AI mode and use
**Load server AI configuration** if the operator prepared SECAUDIT_AI_CONFIG.
The file supplies the exact endpoint, model, pins and budgets; an API key alone
cannot establish these settings. See AI_QUICKSTART.md.

Loading configuration sends no provider request and accepts no disclosure on your
behalf. It reports CONFIGURED_NOT_TESTED or CREDENTIAL_MISSING. Accept metadata
disclosure and start the assessment to run provider readiness and inference.
Offline/web-only non-AI modes do not depend on provider availability.

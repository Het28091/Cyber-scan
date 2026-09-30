# Reusable assessment profiles

Feature-first implementation, 30 September 2026. **UNVERIFIED**: testing and
debugging are deferred. No earlier test result validates these additions.

Open **New assessment** to use the reusable setup panel:

1. Configure a source directory and/or target, scope, optional workflows,
   scanners and provider in either editor.
2. Choose **Review configuration** to see the mode, source/target, permitted and
   excluded prefixes, IP pins, limits, declared operations and provider disclosure.
3. Enter a profile name and choose **Save as new**. **Update selected** updates
   an existing profile; **Save as new** also creates a copy of loaded settings.
4. Select a profile and choose **Load selected** to populate the advanced JSON
   editor. Review authorization and current pins, then explicitly accept the
   assessment authorization and any AI disclosure before starting.
5. **Delete selected** removes only the selected configuration, not scan evidence.

Selecting an item alone does not replace the form. Loading a profile does replace
the form and clears a selected ZIP and both consent checkboxes. Profiles in disabled
AI modes cannot be loaded until that experimental mode is enabled on the server.
The guided editor does not import loaded JSON; use advanced JSON for loaded profiles
or explicitly switch to the independent guided fields for a new setup.

Profiles persist locally in `profiles.sqlite3` within the dashboard output
directory. Up to 100 named profiles are retained, each with a revision and updated
timestamp. Updates/deletions reject stale revisions. No automatic scheduling or
scan starts are performed. Filesystem permissions restrict ordinary access, but
this is not an encrypted credential vault or a multi-user authorization system.

Saved fields include source paths, target, preset, scope, target workflow, scanner
settings and optional provider configuration. ZIP contents, uploaded archive names,
job IDs, authorization checkbox state and provider consent are not saved. Source
archives cannot be saved or summarized through this panel; use a source directory
or target for reusable setups. Credential fields retain environment-variable names;
never place actual secrets in profile names, authorization text or other free text.

Reviewing/saving performs structural configuration validation, not readiness
testing. It does not resolve DNS, inspect local files, read credential variables,
contact targets/providers, or validate installed tools. A saved profile is not
authorization to reuse an old target or evidence that IP pins remain current.
Normal job submission and preflight continue to apply before execution. The request
summary counts explicit workflow operations (including four session operations),
not passive crawl traffic or AI requests.

Authenticated dashboard endpoints:

- `GET /api/profiles` lists profiles and their configuration.
- `POST /api/profiles` accepts `name`, `configuration` and, for updates, `id` and
  `revision`. New profiles start at revision zero.
- `POST /api/profiles/ID/delete` accepts the current `revision`.
- `POST /api/configuration/preview` accepts a configuration and returns its summary.

Mutation endpoints use the existing dashboard origin and CSRF controls. Profile
configuration is bounded to 100 KB and excludes unknown top-level fields.

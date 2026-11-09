# Changelog

## 0.6.0

New capabilities layered on top of the existing tripwire. The bait path tripwire, fake value detection, request
redaction and lockdown are unchanged, and the bait tripwire is still the only rule that blocks on its own.

- **Session event log.** In memory, at most 50 events per session (oldest dropped) and 200 sessions. Each event
  keeps only a type tag (untrusted-content-read, credential-recon, file-staging, encoding-or-transform,
  outbound-attempt, bait-hit), the tool name and a short masked label (a host, a shortened path or a command name).
  It never keeps full tool arguments, file contents or fake values. It is recorded after the tripwire has decided,
  in its own error handling.
- **Incident reports.** Each incident now records its outcome (blocked, escalated to approval, or redacted), a
  severity, whether lockdown is active for the session, and the session's last few events. `/customs incidents`
  and the alerts show them. New `/customs export [N]` writes the last N incidents (default 50) as sanitized JSON to
  `incidents-export.json` in the plugin's data folder, readable only by you.
- **`/customs check` self-test.** Each detector runs on made-up inputs and gets its own PASS, FAIL or ERROR line.
  PASS is printed only when the checks ran and all held. It reads no user file, writes nothing and sends nothing.
- **Decoy integrity in `/customs status`.** Each registered decoy is reported as intact, missing, modified (some
  fake values gone), replaced (a symlink, a non-regular file, or a file holding none of its fake values),
  registry-inconsistent or unreadable, with a warning when coverage drops, for example "6 registered decoys,
  4 intact". It only reports: it never recreates, overwrites or deletes anything.
- **Chain correlation, approval only.** When a call would send data out and the same session, within 30 minutes,
  earlier searched for credentials and then packaged something clearly about credentials (or both archived and
  encoded), customs records a high-severity incident and asks you to approve the call. It never blocks, never
  claims the steps are connected, ignores single signals and plain compression, and lets the call through if it
  hits an error.

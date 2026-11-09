# Changelog

## 0.6.3

- Script inspection and the pipe-into-a-shell approval now run even before any bait is planted. With no bait there
  is nothing to match paths or values against, but a local script is still read before it runs.
- `.bait.lock` is created with mode 600, and an existing lock file is tightened to 600.
- README corrected to match the code, with the limits listed plainly.

## 0.6.2

- The likely source of an incident now comes only from a call that actually read something. A web, browser or
  terminal fetch that failed (an error status, an error or `success: false` in the result, a fetch whose results
  all failed or came back empty, a non-zero exit code, or a file that wasn't found) is no longer recorded as a source.
  The session trail still tags it as `untrusted-content-attempt`.
- New README.

## 0.6.1

Display changes only. Detection, correlation and the core files are unchanged.

- An approval request is labelled ASKED (never "APPROVE") in `/customs incidents`, alerts and the export. When
  Hermes reports a person's answer (its `post_approval_response` hook, a new observer that changes nothing), the
  incident's outcome becomes "user approved" or "user denied". Timeouts, cancellations and automatic decisions
  are not recorded as a user decision; the outcome stays "escalated to approval".
- `/customs incidents` hides `bait=` when there is no bait file.
- A web or browser call that failed is logged as `untrusted-content-attempt`, since nothing was read. Chain
  correlation doesn't use this tag.
- Alerts (chat and push) are laid out for a phone: a `customs · BLOCKED`, `customs · ASKED FOR APPROVAL` or
  `customs · REDACTED` line and the severity, then short labelled sections. Every URL and domain is defanged
  (`hxxps://`, `[.]`) so it can't be tapped; the incident log and export keep the real text. Paths, commands
  and steps are sent as inline code so Telegram formatting can't change them.

## 0.6.0

New capabilities layered on top of the existing tripwire. The bait path tripwire, fake value detection, request
redaction and lockdown are unchanged, and none of the new capabilities blocks a call: blocks still come only from the
existing rules (a bait path, a fake value in a tool's arguments, or a script that both hunts and uploads).

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

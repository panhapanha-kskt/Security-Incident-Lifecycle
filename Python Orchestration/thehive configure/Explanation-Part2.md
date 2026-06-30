# Part 2: TheHive + Cortex + Gmail Integration

Here's Part 2 broken down the same way as Part 1 — phase by phase, every step explained in plain language, tracing the actual code path through `thehive-intercept.py` and its supporting modules.

## Phase 1 — Startup & Connection Setup

1. **Program starts** — `main()` runs, signal handlers for SIGTERM/SIGINT are registered (same graceful-shutdown pattern as Part 1), and logging is configured to write to `thehive_interceptor.log`.

2. **Check for required credentials** — The program checks if `THEHIVE_KEY` was set as an environment variable. If it's missing, the program refuses to start and prints an error telling you what to export. (As I flagged earlier, this error message currently has real-looking example credentials hardcoded into it — that needs fixing, but functionally this step is just a safety gate so the program never runs without authentication.)

3. **Connect to TheHive** — A `TheHiveClient` object is created, which wraps a `requests.Session` with the API key attached as a Bearer token header. Unless running in `--dry-run` mode, it calls `client.ping()` — a simple GET to TheHive's status endpoint — to confirm the connection actually works before doing anything else. If TheHive is unreachable, the program doesn't crash; it logs a warning and keeps running in terminal-only mode, so you still get visibility even if the case-management backend is down.

4. **Set up Gmail alerting (optional)** — If `GMAIL_USER`, `GMAIL_PASS`, and `ALERT_TO` are all present, a `GmailAlerter` is created. If any are missing, email alerting is simply disabled for this run — the rest of the system still works, just without email notifications.

5. **Check input files exist** — Same as Part 1: it warns if `alerts.json` or `archives.json` don't exist yet, in case Wazuh hasn't started writing to them.

6. **Initialize all the tracking objects** — A file tailer (`MultiTailer`), a correlation engine (`Correlator`), a day-boundary tracker, a dedup tracker, a brute-force tracker, and a fresh counters dictionary (which now includes TheHive-specific and email-specific counters, not just severity counts) are all created and ready before the main loop begins.

## Phase 2 — Reading & Building the Alert (identical foundation to Part 1)

7. **Day rollover check** — At the top of every loop cycle, the program checks if local midnight has passed. If so, it prints a daily summary, resets every tracker (counters, dedup, brute-force tracker, correlator, the case manager's dedup memory, and Gmail's dedup memory), and starts the new day fresh.

8. **Read new lines from both files** — Same polling approach as Part 1: check both `alerts.json` and `archives.json` for new content.

9. **Parse and normalize the alert** — The exact same `build_alert()` function from Part 1 is reused here, so every alert is converted into the same standardized format.

10. **Date filter** — If the alert isn't from today, it's skipped and counted, same as before.

11. **Brute-force escalation** — Login-failure-type alerts get their severity bumped based on how many failures that source IP has racked up in the last 5 minutes, exactly the same logic as Part 1.

12. **Severity gate** — If the alert's severity is below the configured minimum, it's dropped and counted as skipped.

13. **Dedup check** — Same composite-key duplicate detection (rule + agent + source IP + file path) within the 30-second window.

14. **Display on screen** — The alert is shown in the terminal exactly as in Part 1. This step is unchanged — every alert that survives filtering still gets a visual readout.

## Phase 3 — Creating a Case in TheHive

15. **Decide whether to open a case** — `manager.process_alert(alert)` is called. Inside this, there's a *second*, independent severity check — TheHive specifically requires at least MEDIUM severity (`CASE_MIN_SEVERITY`) to open a case, even if the alert already passed the lower terminal-display threshold. This means some alerts get displayed on screen but never become a formal TheHive case — intentional, so TheHive doesn't get cluttered with low-priority noise while the terminal still shows everything.

16. **Case-level dedup check** — Separately from the alert-level dedup in step 13, the case manager checks if a case for this exact `rule_id + srcip` combination was already created within the last 10 minutes (`CASE_DEDUP_SEC`). This stops the same ongoing incident from spawning dozens of duplicate TheHive cases while it's still active.

17. **Build the case structure** — If it passes both checks, a structured case is assembled: a title like `[HIGH] Rule 100101 — Reverse shell tool detected`, a markdown table description with all the key fields (timestamp, rule, severity, source/dest IP, agent, MITRE tags), and a hidden HTML comment block containing the same data as raw JSON (since TheHive 5 Community Edition's official "custom fields" feature doesn't actually work, this hidden JSON block is the workaround). Tags are also attached for the same data — agent ID, source IP, agent IP — because tags are the more reliable way to retrieve this information later.

18. **Submit the case to TheHive's API** — Unless in dry-run mode, this is sent via `POST /api/v1/case`. If successful, the case ID comes back and the case is now visible in TheHive's UI for an analyst to work. If it fails (network error, API rejection), the failure is logged but the program keeps running rather than crashing.

## Phase 4 — Adding Evidence (Observables) to the Case

19. **Extract observables from the alert** — `ObservableExtractor.extract()` scans every field of the alert — source/dest IPs, Suricata fields, Zeek fields, raw log text, syscheck hash fields for file-integrity events — and pulls out anything that looks like meaningful evidence: IP addresses, user-agent strings, file hashes (MD5/SHA1/SHA256). It even runs regex scans across free-text fields (description, full log) to catch IPs or user-agents that weren't in a structured field.

20. **Filter to allowed types** — Only `ip`, `user-agent`, and `hash` observable types are kept; anything else extracted gets quietly dropped (and counted as "skipped" in the summary).

21. **For each observable, decide its classification** — For every piece of evidence, the program decides: is this an IOC (indicator of compromise, meaning it should be flagged as a known-bad indicator)? Is it "sighted" (meaning it was actually observed inside your network, as opposed to just referenced)? What TLP/PAP sensitivity level should it carry (private internal IPs get marked lower-sensitivity than public ones; file hashes always get treated as more sensitive)?

22. **Post each observable to TheHive** — Each piece of evidence is submitted individually via the API. The program handles three outcomes: a brand-new observable gets created, an already-existing duplicate gets its metadata updated instead of creating a second copy, and genuine failures get logged with the specific error.

## Phase 5 — Triggering Automated Threat Intelligence (Cortex Analyzers)

23. **Load the list of available Cortex analyzers** — The first time this runs, it queries TheHive for which Cortex analyzers are actually configured and available (VirusTotal, Shodan, MISP, etc.) and caches that list so it doesn't have to re-query every single time.

24. **Fire the relevant analyzers for each observable** — Depending on the observable type, different analyzers get triggered: IP addresses get checked against VirusTotal, Shodan reverse-DNS, and MISP; file hashes get checked against VirusTotal and MISP; user-agents get checked against MISP. Private/internal IP addresses are treated differently — only MISP runs on them, since sending an internal RFC1918 address to VirusTotal or Shodan would be pointless and could even leak internal network information externally.

## Phase 6 — Triggering Automated Response (Active Defense)

25. **Decide if this rule warrants an automatic defensive action** — Certain rule categories — file integrity violations and brute-force/login-failure patterns — are configured to automatically trigger a real defensive action on the affected device, not just a notification. This check happens regardless of whether the observables above were brand new or duplicates, because the threat itself (e.g., an ongoing brute-force from a known-bad IP) still needs blocking even if you've already seen that IP before.

26. **Try Cortex first** — The system attempts to trigger the appropriate Cortex "responder" — either the network responder (which blocks the offending IP via firewall rule) or the FIM responder (which locks down a tampered file by making it immutable). It tries this through Cortex's API first, using known UUIDs for each responder variant.

27. **Fall back to direct Wazuh API if Cortex fails** — If the Cortex route fails (connector down, UUID mismatch, etc.), the system doesn't give up — it falls back to calling the Wazuh Manager's own REST API directly, dispatching the same active-response command (firewall-drop or fim-respond) straight to the affected agent. To do this, it has to first re-fetch the case data from TheHive and extract the agent ID and source IP back out of the tags or the hidden metadata block.

28. **Log the outcome distinctly** — The result is categorized as one of three things: successfully triggered, expectedly skipped (for example, a correlation case with no specific source IP to act on — that's not a real failure), or genuinely failed (a real error worth investigating). This distinction matters so your statistics don't make legitimate skips look like system errors.

## Phase 7 — Email Alerting

29. **Send an email if Gmail is enabled and not in dry-run mode** — Using the same `GmailAlerter` logic as Part 1, with its own independent severity threshold and dedup window, so email notifications follow their own rules separate from when a TheHive case gets created.

## Phase 8 — Correlation (Same Engine, Now With Case Creation)

30. **Run the same correlation engine from Part 1** — Archive entries are excluded; real rule detections get added to the correlation engine's short-term memory and checked against the five known attack-pattern signatures.

31. **If a correlation match is found, it also gets its own TheHive case** — This is the key addition over Part 1: a correlation match doesn't just print a banner anymore, it creates a dedicated TheHive case representing the multi-step attack pattern, with its own dedup logic (keyed by signature name + agent, not rule + source IP). If a network responder makes sense for the correlation, it's triggered the same way as in Phase 6. If Gmail is enabled, a correlation-specific email is also sent, built from a synthetic alert dict assembled from the correlation result.

## Phase 9 — Logging, Maintenance & Shutdown

32. **Write the final structured log line for every processed alert** — Records the disposition of every alert regardless of what happened to it.

33. **Periodic cleanup** — Every 100 loop cycles, expired entries are purged from the dedup tracker, the brute-force tracker, the case manager's dedup memory, and Gmail's dedup memory, so none of these dictionaries grow unbounded over a long-running session.

34. **Periodic statistics printout** — Every 300 cycles, both the standard severity stats and a TheHive/Gmail-specific integration stats line are printed, showing how many cases were created, how many were dedup-skipped, how many responders succeeded/were skipped/failed, and how many emails sent/failed.

35. **Shutdown** — Same as Part 1: on SIGTERM/SIGINT, the loop exits cleanly, prints a final shutdown summary with the full set of counters (including all the TheHive/responder/email stats this time), logs it, and exits.

That's the complete trace of Part 2, boss — every step of how a Wazuh alert turns into a TheHive case, gets enriched with evidence and threat intel, and can ultimately trigger a real automated defensive action on the affected machine.

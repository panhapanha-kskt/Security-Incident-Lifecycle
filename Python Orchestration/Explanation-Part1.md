# Step-by-Step Explanation

## Phase 1: Ingestion (`intercept.py`, `config.py`)

This is where the system starts watching for security events.

1. **Interceptor Starts**: The program turns on. It tells the operating system "if anyone tries to stop me, let me shut down properly instead of just dying." It sets up its logging so everything gets recorded to a file. Then it gets ready to watch two specific files on the server.
2. **Multi Alert**: Collect alerts from `alerts.json` and `archives.json`. The program watches two separate files at the same time: one is the "important alerts" file, the other is a "raw archive" file that records everything, even things not flagged as alerts. It keeps an independent bookmark in each file so it always knows exactly where it last stopped reading.
3. **New Line Available?**: Every fraction of a second, it checks both files: "has anything new been written since I last checked?"
   - If no, it waits a moment and checks again.
   - If yes, it grabs that new piece of text and moves forward immediately.
4. **Sleep 0.1 seconds**: If nothing new showed up, instead of checking thousands of times per second and wasting computer resources, it pauses briefly, then loops back to check again. This keeps the program lightweight while still being fast enough to feel "real-time."

## Phase 2: Parse & Build (Making sense of the raw data)

5. **Parse the line of text**: The new piece of text is technically just a string of characters. The program tries to interpret it as structured data.
   - If it's broken or corrupted, it's thrown away and a quiet note is logged, but the program keeps running.
   - If it's valid, it moves on.
6. **Build a clean alert record**: Raw security data from Wazuh can look very different depending on what detected it — a file change, a network signature, a login attempt, etc. This step takes whatever messy shape the data came in and reorganizes it into one consistent, predictable format that the rest of the program can work with no matter the source.
7. **Is this alert from today?**: The program checks the alert's timestamp against today's date in your local timezone.
   - If it's an old, leftover alert from a previous day, it's discarded so it doesn't distort today's statistics.
   - If it's current, it moves forward.

## Phase 3: Classify & Filter (Deciding how serious it is, and removing noise)

8. **Classify the rule's severity**: The program checks its own curated list of known dangerous behaviors first (the worst ones), then less severe ones, and only if nothing matches does it fall back to a generic numeric severity score. This way, specifically named threats always get labeled clearly rather than just "medium risk."
9. **Attach MITRE ATT&CK technique tags**: Every classified threat gets tagged with the official attacker technique it resembles (e.g. brute force, privilege escalation), combining the program's own knowledge with anything Wazuh itself already tagged, so nothing gets duplicated.
10. **Is it severe enough to bother showing?**: There's a minimum severity threshold. If the alert is below that bar, it's quietly dropped and just counted as "skipped". This is the main spam filter for genuinely trivial events.
11. **Is this a duplicate of something just seen?**: The program checks if the exact same type of event, from the same device, same source address, and same file, was already reported in the last 30 seconds.
    - If yes, it's dropped as a duplicate so the same incident doesn't get reported repeatedly every fraction of a second.
    - If no, it's treated as a fresh, unique event and moves forward.

## Phase 4: Catching attacks made of many small failures

12. **Is this a login-failure type event?**: Some events (like a single failed SSH login) aren't dangerous in isolation, but become dangerous in volume.
    - If it's not that type of event, it skips ahead unchanged.
    - If it is, the program starts paying closer attention.
13. **Record this failure for that attacker's IP address**: The program keeps a running tally of how many failures have come from this specific IP in roughly the last 5 minutes, automatically forgetting failures older than that window.
14. **Decide if the severity should be escalated**: If that IP has racked up enough failures in the time window, the program automatically upgrades the severity of the alert: a moderate number of failures bumps it to Medium, more bumps it to High, and a very high number bumps it all the way to Critical. This is how a single innocuous-looking login failure becomes flagged as an active brute-force attack once the pattern is clear.

## Phase 5: Output & Display (Showing the result)

15. **Update the running statistics**: Whatever severity the alert ended up at, the program adds one to its running totals — overall count, count per severity level, and which file it came from.
16. **Display the alert on screen**: The program prints a clean, color-coded summary block to the terminal: when it happened, what triggered it, how severe it is, what device it came from, and any relevant technical details (file paths, IP addresses, signatures), formatted to look like a professional SOC dashboard.

## Phase 6: Correlation Engine (Connecting the dots between separate events)

17. **Is this just an archive entry, not a real alert?**: Archive entries are raw logs, not actual triggered detections.
    - If yes, it's excluded from pattern-matching since it's not a real signal.
    - If no, it gets fed into the pattern-detection engine.
18. **Record this event for pattern matching**: The program remembers "this device just triggered this specific type of event," and forgets anything that happened more than 5 minutes ago, so only recent, related activity counts.
19. **Check for known dangerous combinations**: The program has a list of known "this plus that equals serious trouble" patterns — for example, a brute-force login success followed by a privilege escalation attempt, or a port scan followed by a SQL injection attempt. It checks if any single device has triggered both halves of one of these patterns recently, while making sure it doesn't repeatedly re-alert on the exact same already-flagged combination.
20. **Was a dangerous combination found?**:
    - If yes, a special, more urgent "correlation alert" banner is displayed. this represents the system recognizing a multi-step attack pattern, not just an isolated single event.
    - If no, the program simply continues without raising extra alarm.

## Phase 7 — Email Alerting (Notifying a human directly)

21. **Is this severe enough to deserve an email?**: Only the more serious severity levels (Critical, High, Medium) ever trigger an email. Minor events stay on-screen only.
    - If not severe enough, no email is sent.
    - If severe enough, it checks one more thing before sending.
22. **Has an email for this exact situation already gone out recently?**: To avoid flooding an inbox with repeated emails about the same ongoing issue, the program checks if it already emailed about this specific rule and source IP within the last 5 minutes.
    - If yes, it skips sending again.
    - If no, it proceeds to actually send.
23. **Send the email notification**: The program builds a nicely formatted email (with a summary, technical details, and recommended next steps for an analyst) and sends it through Gmail.
    - If the email server connection fails for some technical reason, that failure is specifically logged as a delivery error, distinct from a normal "we chose not to send" skip.
    - If it sends successfully, it's recorded so the same alert doesn't trigger another email too soon.
24. **Write a final log entry** — No matter what happened above. sent, skipped, or failed, a permanent record of the decision is written to the log file, so there's always an audit trail of exactly what the system decided to do and why.

## Phase 8: Day Boundary & Shutdown (Daily resets and stopping safely)

25. **Has the day changed?** — The program checks if local midnight has passed since it last checked.
    - If yes, it prints and logs a full daily summary report — how long it ran, how many alerts of each severity, etc. — and then resets all its counters and short-term memory for the new day.
    - If no, it just moves on.
26. **Was a stop request received?**: The program checks if it was asked to shut down (by someone stopping the service, or pressing Ctrl+C).
    - If no, it loops all the way back to the very beginning and starts watching for the next new line of data.
    - If yes, it proceeds to shut down.
27. **Final shutdown**: The program prints one last summary of everything that happened during this run, writes it to the log, and exits cleanly, making sure nothing is left in a half-finished state.

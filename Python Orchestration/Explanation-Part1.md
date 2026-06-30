Phase 1: Ingestion (Intercept.py, config.py)
This is where the system starts watching for security events.
1. Interceptor Starts: The program turns on. It tells the operating system "if anyone tries to stop me, let me shut down properly instead of just dying." It sets up its logging so everything gets recorded to a file. Then it gets ready to watch two specific files on the server.
2. Multi Alert: Collect alerts from alerts.json and archives.json. The program watches two separate files at the same time: one is the "important alerts" file, the other is a "raw archive" file that records everything, even things not flagged as alerts. It keeps an independent bookmark in each file so it always knows exactly where it last stopped reading.
3. New Line Available?: Every fraction of a second, it checks both files: "has anything new been written since I last checked?" 
  . If no, it waits a moment and checks again.
  . If yes, it grabs that new piece of text and moves forward immediately.
4. Sleep 0.1 seconds: If nothing new showed up, instead of checking thousands of times per second and wasting computer resources, it pauses briefly, then loops back to check again. This keeps the program lightweight while still being fast enough to feel "real-time."

Phase 2: Parse & Build (Making sense of the raw data)
5. Parse the line of text: The new piece of text is technically just a string of characters. The program tries to interpret it as structured data.
  . If it's broken or corrupted, it's thrown away and a quiet note is logged, but the program keeps running.
  . If it's valid, it moves on.
6. Build a clean alert record: Raw security data from Wazuh can look very different depending on what detected it — a file change, a network signature, a login attempt, etc. This step takes whatever messy shape the data came in and reorganizes it into one consistent, predictable format that the rest of the program can work with no matter the source.
7. Is this alert from today?: The program checks the alert's timestamp against today's date in your local timezone.
  . If it's an old, leftover alert from a previous day, it's discarded so it doesn't distort today's statistics.
  . If it's current, it moves forward.

Phase 3: Classify & Filter (Deciding how serious it is, and removing noise)
8. Classify the rule's severity: The program checks its own curated list of known dangerous behaviors first (the worst ones), then less severe ones, and only if nothing matches does it fall back to a generic numeric severity score. This way, specifically named threats always get labeled clearly rather than just "medium risk."
9. Attach MITRE ATT&CK technique tags: Every classified threat gets tagged with the official attacker technique it resembles (e.g. brute force, privilege escalation), combining the program's own knowledge with anything Wazuh itself already tagged, so nothing gets duplicated.
10. Is it severe enough to bother showing?: There's a minimum severity threshold. If the alert is below that bar, it's quietly dropped and just counted as "skipped". This is the main spam filter for genuinely trivial events.
11. Is this a duplicate of something just seen?: The program checks if the exact same type of event, from the same device, same source address, and same file, was already reported in the last 30 seconds.
  . If yes, it's dropped as a duplicate so the same incident doesn't get reported repeatedly every fraction of a second.
  . If no, it's treated as a fresh, unique event and moves forward.

Phase 4: Catching attacks made of many small failures
12. Is this a login-failure type event?: Some events (like a single failed SSH login) aren't dangerous in isolation, but become dangerous in volume.
  . If it's not that type of event, it skips ahead unchanged.
  . If it is, the program starts paying closer attention.
13. Record this failure for that attacker's IP address: The program keeps a running tally of how many failures have come from this specific IP in roughly the last 5 minutes, automatically forgetting failures older than that window.
14. Decide if the severity should be escalated: 

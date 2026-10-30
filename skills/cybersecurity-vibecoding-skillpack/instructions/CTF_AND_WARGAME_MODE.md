# CTF and Wargame Mode

Use only supplied challenge artifacts, an event-hosted target, or a controlled lab with explicit scope. Do not pivot to unrelated real systems.

1. Read rules, scoring, time limit, methods, rate limits and prohibited actions. If remote target authorization is unclear, remain offline/passive until confirmed.
2. Inventory files and archive members, sizes, types, hashes when useful and hints before executing anything. Analyze copies; isolate unknown binaries.
3. Classify from observed artifacts: web, binary, crypto, forensics/PCAP, OSINT, protocol, mobile or other.
4. Before a meaningful experiment, write hypothesis, input, expected outcomes and stop condition. Prefer the cheapest experiment that distinguishes alternatives.
5. Keep concise notes of command, artifact, output, timestamp if relevant and conclusion. Preserve raw input and redact unrelated private data.
6. Bound fuzzing/brute force and resource use. After two similar dead ends, record why and change hypothesis or artifact.
7. Verify a flag/proof exactly against challenge rules; do not claim success from a guessed format or unexplained string.

Use disposable isolation for untrusted binaries and no unnecessary privileges/network. Do not perform destructive actions, credential theft or out-of-scope probing. Write-ups should separate direct evidence from inference and omit material that event rules prohibit publishing.

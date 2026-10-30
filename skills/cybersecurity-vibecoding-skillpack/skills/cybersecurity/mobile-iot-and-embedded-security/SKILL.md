---
name: mobile-iot-and-embedded-security
description: Assess application permissions, firmware and device protocol boundaries in a controlled lab.
triggers:
  - Mobile package, firmware, device or embedded protocol is in scope
  - Permissions, update process, debug interface or local storage needs review
---

# Mobile, IoT and Embedded Security

## Purpose
Assess application permissions, firmware and device protocol boundaries in a controlled lab.

## Use When
- Mobile package, firmware, device or embedded protocol is in scope
- Permissions, update process, debug interface or local storage needs review

## Do Not Load When
- Ordinary web/server app with no device context.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Artifact/model/version, ownership authorization, package permissions, lab environment and protocol docs.

## Procedure
1. Inventory artifact type/version/hash, permission list and test environment.
2. Test only owned devices, emulators or supplied firmware; never devices or networks you do not control.
3. Check static properties: permissions, exported components, cleartext traffic, hard-coded secrets, debug flags, update signature verification.
4. Evaluate local storage, transport security, backend authentication and update paths with safe fixtures.
5. Record device and firmware version, hardware safety limits and what could not be tested.

## Decision Rules and Stop Conditions
- Inspect manifests, exported components, sensitive storage and update trust.
- Unpack firmware on copies; identify filesystems, components and configuration safely.
- Trace local/network protocol boundaries and validate input handling.
- Use owned devices or emulator; protect safety-critical/shared hardware.
- Test least privilege, signed updates and parser handling using safe fixtures.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Avoid testing without authorization or bricking/interrupting shared or safety-critical devices. Protect personal/device identifiers. An exported component is a lead; confirm whether protected operations are reachable and authorized in a controlled app.

## Verification and Acceptance Criteria
Findings reference artifact/code evidence plus model/version assumptions and limits.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Bricking hardware, strings treated as proof, exposed device IDs, update rollback ignored.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Artifact inventory, permission/protocol map, findings and safe remediation tests.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
reverse-engineering-and-binary-analysis; web-and-api-security; privacy-and-data-protection.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Prefer static unpacking/emulators before physical-device testing.

#!/usr/bin/env python3
# Verify an upgraded pack still contains every file and skill of an earlier pack (directory or ZIP). Standard library only.
from __future__ import annotations
import argparse, hashlib, re, sys, tempfile, zipfile
from pathlib import Path, PurePosixPath

def load(source: Path):
    """Return {relative_path: bytes} for a pack directory or a ZIP with one top-level folder."""
    files = {}
    if source.is_file() and source.suffix.lower() == '.zip':
        with zipfile.ZipFile(source) as zf:
            names = [n for n in zf.namelist() if n and not n.endswith('/')]
            roots = {PurePosixPath(n).parts[0] for n in names}
            if len(roots) != 1: raise ValueError(f'ZIP must have one top-level folder, found {sorted(roots)}')
            for n in names: files[PurePosixPath(*PurePosixPath(n).parts[1:]).as_posix()] = zf.read(n)
    elif source.is_dir():
        for p in sorted(source.rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts: files[p.relative_to(source).as_posix()] = p.read_bytes()
    else: raise ValueError(f'Not a directory or ZIP: {source}')
    return files

def skill_names(files):
    out = {}
    for rel, data in files.items():
        if re.fullmatch(r'skills/.+/SKILL\.md', rel):
            m = re.search(r'(?m)^name:\s*([a-z0-9-]+)\s*$', data.decode('utf-8', 'replace')); out[rel] = m.group(1) if m else None
    return out

def compare(original: Path, upgraded: Path):
    a, b = load(original), load(upgraded)
    missing_files = sorted(set(a) - set(b)); added = sorted(set(b) - set(a))
    changed = sorted(r for r in set(a) & set(b) if hashlib.sha256(a[r]).digest() != hashlib.sha256(b[r]).digest())
    sa, sb = skill_names(a), skill_names(b)
    missing_skills = sorted(f'{rel} ({n})' for rel, n in sa.items() if rel not in sb or sb[rel] != n)
    return dict(original_files=len(a), upgraded_files=len(b), original_skills=len(sa), upgraded_skills=len(sb),
                missing_files=missing_files, missing_skills=missing_skills, added=added, changed=changed,
                unchanged=len(set(a) & set(b)) - len(changed))

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--original', type=Path, required=True, help='earlier pack directory or ZIP')
    ap.add_argument('--upgraded', type=Path, default=Path(__file__).resolve().parent.parent)
    a = ap.parse_args(argv)
    try: r = compare(a.original, a.upgraded)
    except (OSError, ValueError, zipfile.BadZipFile) as exc: print(f'FAIL: {exc}', file=sys.stderr); return 1
    print(f"files: original {r['original_files']}, upgraded {r['upgraded_files']}; skills: original {r['original_skills']}, upgraded {r['upgraded_skills']}")
    print(f"unchanged {r['unchanged']}, modified {len(r['changed'])}, added {len(r['added'])}")
    if r['missing_files'] or r['missing_skills']:
        print(f"FAIL: {len(r['missing_files'])} original file(s) missing, {len(r['missing_skills'])} original skill(s) missing or renamed")
        for x in r['missing_files'] + r['missing_skills']: print(' - ' + x)
        return 1
    print('PASS: every original file and skill is present with its original path and name'); return 0
if __name__ == '__main__': raise SystemExit(main())

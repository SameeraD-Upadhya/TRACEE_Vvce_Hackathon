#!/usr/bin/env python3
# Validate pack structure and archive with the Python standard library.
from __future__ import annotations
import argparse, json, re, sys, zipfile
from pathlib import Path, PurePosixPath
REQUIRED_DIRS=['instructions','platform-guides','skills/core','skills/cybersecurity','skills/engineering','templates','examples','scripts','tests']
REQUIRED_FILES=['README.md','START_HERE.md','AGENTS.md','SKILL_ROUTER.md','MANIFEST.json','VERSION','CHANGELOG.md',
'instructions/ADAPTIVE_MASTER_WORKFLOW.md','instructions/HACKATHON_MODE.md','instructions/PROJECT_BUILD_MODE.md','instructions/PROJECT_AUDIT_MODE.md','instructions/CTF_AND_WARGAME_MODE.md','instructions/DEFENSIVE_SOC_DFIR_MODE.md','instructions/RESEARCH_AND_PAPER_MODE.md','instructions/FINAL_DEMO_AND_SUBMISSION.md',
'platform-guides/CLAUDE_CODE.md','platform-guides/OPENAI_CODEX.md','platform-guides/ANTIGRAVITY.md','platform-guides/CURSOR.md','platform-guides/GEMINI_CODING_TOOLS.md','platform-guides/GITHUB_COPILOT.md','platform-guides/PORTABLE_MARKDOWN_AGENTS.md',
'templates/challenge-brief.md','templates/project-context.md','templates/scope-and-rules.md','templates/acceptance-criteria.md','templates/task-board.md','templates/decision-log.md','templates/threat-model.md','templates/test-plan.md','templates/bug-report.md','templates/security-finding.md','templates/evidence-record.md','templates/architecture-decision-record.md','templates/demo-script.md','templates/judging-rubric-matrix.md','templates/final-report.md','templates/handoff-and-known-limitations.md','examples/ROUTING_EXAMPLES.md','examples/SAMPLE_PROJECT_CONTEXT.md','scripts/validate_pack.py','scripts/init_project_context.py','scripts/build_zip.py','tests/test_pack_validation.py','instructions/COMMON_SKILL_RULES.md','skills/INDEX.md','templates/claims-ledger.md','scripts/build_index.py','scripts/check_preservation.py','tests/test_pack_integrity.py']
SECTIONS=['Purpose','Use When','Do Not Load When','Required Context and Prerequisites','First 5-Minute Actions','Procedure','Decision Rules and Stop Conditions','Tooling and Fallbacks','Implementation Patterns / Examples','Verification and Acceptance Criteria','Failure Modes and Troubleshooting','Outputs to Record','Related Skills and Activation Triggers','Completion Checklist']
PLACEHOLDER=re.compile(r'\b(?:TODO|TBD|fill this in|implement later)\b',re.I)
SECRET_PATTERNS=[('private key header',re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),('likely cloud access key',re.compile(r'\bAKIA[0-9A-Z]{16}\b')),('likely GitHub token',re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{30,}\b')),('generic credential assignment',re.compile(r'''(?i)\b(?:password|api[_-]?key|secret|token)\s*[:=]\s*["'][^"']{12,}["']'''))]

def skill_paths(root): return sorted(root.glob('skills/**/SKILL.md'))
def validate_zip(zip_path, expected_root='cybersecurity-vibecoding-skillpack'):
 issues=[]
 if not zip_path.exists(): return [f'ZIP missing: {zip_path}']
 try:
  with zipfile.ZipFile(zip_path) as zf:
   bad=zf.testzip()
   if bad: issues.append(f'ZIP integrity failure at: {bad}')
   names=[n for n in zf.namelist() if n and not n.endswith('/')]
   roots={PurePosixPath(n).parts[0] for n in names if PurePosixPath(n).parts}
   if not names: issues.append('ZIP contains no files')
   if roots!={expected_root}: issues.append(f'ZIP must have exactly top-level root {expected_root!r}; got {sorted(roots)}')
   for n in names:
    pp=PurePosixPath(n)
    if pp.is_absolute() or '..' in pp.parts or '\\' in n:
     issues.append(f'Unsafe/non-portable ZIP path: {n}'); break
   for rel in REQUIRED_FILES:
    if f'{expected_root}/{rel}' not in names: issues.append(f'ZIP missing required file: {expected_root}/{rel}')
   mname=f'{expected_root}/MANIFEST.json'
   if mname in names:
    try: manifest=json.loads(zf.read(mname).decode('utf-8'))
    except Exception as exc: issues.append(f'ZIP manifest unreadable: {exc}'); manifest={}
    for rel in manifest.get('skills',[]):
     if f'{expected_root}/{rel}' not in names: issues.append(f'ZIP missing manifest skill: {rel}')
 except (OSError,zipfile.BadZipFile) as exc: issues.append(f'Cannot read ZIP: {exc}')
 return issues

def validate_pack(root, zip_path=None):
 issues=[]; root=Path(root).resolve()
 if not root.is_dir(): return [f'Pack root is not a directory: {root}']
 for rel in REQUIRED_DIRS:
  if not (root/rel).is_dir(): issues.append(f'Missing required directory: {rel}')
 for rel in REQUIRED_FILES:
  if not (root/rel).is_file(): issues.append(f'Missing required file: {rel}')
 for path in skill_paths(root):
  txt=path.read_text(encoding='utf-8',errors='replace'); rel=path.relative_to(root).as_posix()
  if not txt.startswith('---\n'): issues.append(f'{rel}: missing opening frontmatter delimiter')
  parts=txt.split('---',2)
  if len(parts)<3: issues.append(f'{rel}: malformed frontmatter')
  else:
   fm=parts[1]
   if not re.search(r'(?m)^name:\s*[a-z0-9-]+\s*$',fm): issues.append(f'{rel}: invalid/missing name metadata')
   if not re.search(r'(?m)^description:\s*\S.+$',fm): issues.append(f'{rel}: invalid/missing description metadata')
   if not re.search(r'(?m)^triggers:\s*$',fm) or not re.search(r'(?m)^\s+-\s+\S',fm): issues.append(f'{rel}: missing trigger list')
  for section in SECTIONS:
   if not re.search(r'(?m)^##\s+'+re.escape(section)+r'\s*$',txt): issues.append(f'{rel}: missing section "{section}"')
  if len(txt.strip())<1800: issues.append(f'{rel}: too short for a substantive playbook ({len(txt)} chars)')
 mpath=root/'MANIFEST.json'; manifest=None
 if mpath.is_file():
  try: manifest=json.loads(mpath.read_text(encoding='utf-8'))
  except (json.JSONDecodeError,OSError) as exc: issues.append(f'MANIFEST.json invalid: {exc}')
 if manifest is not None:
  for k in ('name','version','purpose','last_updated','compatibility_approach','categories','supported_modes','utility_scripts','safety_statement'):
   if k not in manifest: issues.append(f'MANIFEST.json missing key: {k}')
  actual={p.relative_to(root).as_posix() for p in skill_paths(root)}
  if actual!=set(manifest.get('skills',[])): issues.append(f'MANIFEST skill list mismatch: {len(actual)} actual, {len(manifest.get("skills",[]))} listed')
  for cat in ('core','cybersecurity','engineering'):
   expect={p for p in actual if p.startswith(f'skills/{cat}/')}
   if expect!=set(manifest.get('categories',{}).get(cat,[])): issues.append(f'MANIFEST categories.{cat} mismatch')
  for rel in manifest.get('skills',[])+manifest.get('supported_modes',[])+manifest.get('platform_guides',[])+manifest.get('templates',[]):
   if not (root/rel).is_file(): issues.append(f'MANIFEST references missing path: {rel}')
 # Check relative Markdown links; inline code/path mentions are not links and are ignored.
 link_re=re.compile(r'(?<!!)\[[^\]]*\]\(([^)]+)\)')
 md_files=sorted(root.rglob('*.md'))
 for path in md_files:
  txt=path.read_text(encoding='utf-8',errors='replace')
  for target in link_re.findall(txt):
   target=target.strip().split('#',1)[0].strip()
   if not target or re.match(r'^(?:https?://|mailto:|tel:|data:)',target,re.I): continue
   tp=(path.parent/target).resolve() if not target.startswith('/') else (root/target.lstrip('/')).resolve()
   if not tp.exists(): issues.append(f'Broken relative Markdown link in {path.relative_to(root).as_posix()}: {target}')
 for path in md_files:
  rel=path.relative_to(root).as_posix()
  if not rel.startswith('templates/') and PLACEHOLDER.search(path.read_text(encoding='utf-8',errors='replace')):
   issues.append(f'Possible placeholder text in {rel}')
 for path in root.rglob('*'):
  if not path.is_file(): continue
  rel=path.relative_to(root).as_posix()
  if path.name.lower()=='.env' or path.name.lower().startswith('.env.'): issues.append(f'Secret-prone environment file present: {rel}')
  if rel!='scripts/validate_pack.py' and path.suffix.lower() in {'.md','.json','.py','.txt','.yml','.yaml','.toml','.ini','.cfg'}:
   data=path.read_text(encoding='utf-8',errors='replace')
   for label,pattern in SECRET_PATTERNS:
    if pattern.search(data): issues.append(f'Possible {label} in {rel} (heuristic; review manually)')
 issues.extend(extra_checks(root))
 if zip_path is not None: issues.extend(validate_zip(Path(zip_path)))
 return issues


# ---- Additional integrity checks (added in 1.1.0). They only add checks; no original check was relaxed. ----
KEBAB = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)+$')
SKILL_REF = re.compile(r'\b((?:core|cybersecurity|engineering)/[a-z0-9][a-z0-9-]*)')
MAX_SKILL_CHARS = 8000
DUP_MIN_CHARS = 200
DUP_MIN_FILES = 6

def _skill_meta(root):
    metas = {}
    for path in skill_paths(root):
        txt = path.read_text(encoding='utf-8', errors='replace'); m = re.search(r'(?m)^name:\s*([a-z0-9-]+)\s*$', txt)
        metas[path.relative_to(root).as_posix()] = (m.group(1) if m else None, txt)
    return metas

def extra_checks(root):
    issues = []; metas = _skill_meta(root); names = {n for n, _ in metas.values() if n}
    ids = {rel[len('skills/'):-len('/SKILL.md')] for rel in metas}
    # corrupted generated sections
    for rel, (name, txt) in metas.items():
        if len(re.findall(r'(?m)^\d+\. .$', txt)) >= 3: issues.append(f'Corrupted section in {rel}: numbered list with single-character items')
        if re.search(r"(?m)^\[['\"].*['\"]\]\s*$", txt): issues.append(f'Corrupted section in {rel}: Python list text instead of Markdown')
        if len(txt) > MAX_SKILL_CHARS: issues.append(f'Token budget: {rel} is {len(txt)} chars (max {MAX_SKILL_CHARS})')
        parts = rel.split('/')
        if name and name != parts[-2]: issues.append(f'Routing: {rel} name {name!r} differs from directory {parts[-2]!r}')
        sec = re.search(r'(?ms)^##\s+Related Skills and Activation Triggers\s*\n(.*?)(?=^##\s|\Z)', txt)
        if sec:
            first = sec.group(1).strip().split('\n\n')[0]
            for clause in re.split(r';', first):
                token = clause.strip().split(' ')[0].strip('`.,')
                if KEBAB.match(token) and token not in names: issues.append(f'Unresolved related skill in {rel}: {token}')
    # duplicated boilerplate across skills
    counts = {}
    for rel, (name, txt) in metas.items():
        for para in {re.sub(r'^##[^\n]*\n', '', x.strip()) for x in txt.split('\n\n')}:
            if len(para) >= DUP_MIN_CHARS: counts[para] = counts.get(para, 0) + 1
    for para, n in counts.items():
        if n >= DUP_MIN_FILES: issues.append(f'Duplicated boilerplate in {n} skills (move to instructions/COMMON_SKILL_RULES.md): {para[:60]!r}')
    # skill references in router, docs, modes, guides and examples must resolve
    for path in sorted(root.rglob('*.md')):
        rel = path.relative_to(root).as_posix()
        if rel.startswith('skills/') or rel.startswith('templates/'): continue
        for ref in set(SKILL_REF.findall(path.read_text(encoding='utf-8', errors='replace'))):
            if ref not in ids: issues.append(f'Unresolved skill reference in {rel}: {ref}')
    # index must list exactly the existing skills
    index = root / 'skills' / 'INDEX.md'
    if index.is_file():
        listed = set(re.findall(r'\[((?:core|cybersecurity|engineering)/[a-z0-9-]+)\]\(', index.read_text(encoding='utf-8', errors='replace')))
        if listed != ids: issues.append(f'Index: skills/INDEX.md differs from actual skills (missing {sorted(ids - listed)}, extra {sorted(listed - ids)})')
    # version consistency and manifest completeness
    versions = {}
    vfile = root / 'VERSION'
    if vfile.is_file(): versions['VERSION'] = vfile.read_text(encoding='utf-8').strip()
    mpath = root / 'MANIFEST.json'; manifest = {}
    if mpath.is_file():
        try: manifest = json.loads(mpath.read_text(encoding='utf-8')); versions['MANIFEST.json'] = manifest.get('version')
        except json.JSONDecodeError: pass
    cl = root / 'CHANGELOG.md'
    if cl.is_file():
        m = re.search(r'(?m)^##\s+(\d+\.\d+\.\d+)\b', cl.read_text(encoding='utf-8', errors='replace'))
        if m: versions['CHANGELOG.md'] = m.group(1)
    if len(set(versions.values())) > 1: issues.append(f'Version mismatch: {versions}')
    listed_paths = set(manifest.get('templates', [])) | set(manifest.get('supported_modes', [])) | set(manifest.get('platform_guides', [])) | set(manifest.get('shared_files', []))
    for folder in ('templates', 'instructions', 'platform-guides'):
        for f in sorted((root / folder).glob('*.md')) if (root / folder).is_dir() else []:
            rel = f.relative_to(root).as_posix()
            if rel not in listed_paths: issues.append(f'Manifest completeness: {rel} is not listed in MANIFEST.json')
    return issues

def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent); parser.add_argument('--zip',type=Path)
 args=parser.parse_args(argv); problems=validate_pack(args.root,args.zip)
 if problems:
  print(f'FAIL: {len(problems)} issue(s)'); [print(' - '+p) for p in problems]; return 1
 print('PASS: required structure, metadata/sections, manifest, links and hygiene checks')
 print(f'PASS: {len(skill_paths(args.root))} skill playbooks validated')
 if args.zip: print(f'PASS: ZIP structure and integrity validated: {args.zip}')
 return 0
if __name__=='__main__': raise SystemExit(main())

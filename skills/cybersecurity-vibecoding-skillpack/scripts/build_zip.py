#!/usr/bin/env python3
# Build and verify a deterministic ZIP with one top-level source folder.
from __future__ import annotations
import argparse, stat, sys, zipfile
from pathlib import Path, PurePosixPath
EXCLUDED_DIRS={'.git','__pycache__','.pytest_cache','.mypy_cache','.ruff_cache','.venv','venv','node_modules','dist','build','coverage'}
EXCLUDED_NAMES={'.env','.DS_Store','Thumbs.db'}; EXCLUDED_SUFFIXES={'.pyc','.pyo','.zip','.log'}
def eligible(path,root):
 rel=path.relative_to(root)
 return path.is_file() and not any(part in EXCLUDED_DIRS for part in rel.parts[:-1]) and path.name not in EXCLUDED_NAMES and not path.name.lower().startswith('.env.') and path.suffix.lower() not in EXCLUDED_SUFFIXES
def build(root,output):
 root=Path(root).resolve(); output=Path(output).resolve()
 if not root.is_dir(): raise ValueError(f'Pack root does not exist: {root}')
 if output.is_relative_to(root): raise ValueError('Output ZIP must be outside the source pack directory')
 files=sorted((p for p in root.rglob('*') if eligible(p,root)),key=lambda p:p.relative_to(root).as_posix())
 if not files: raise ValueError('No source files found to package')
 output.parent.mkdir(parents=True,exist_ok=True); temp=output.with_suffix(output.suffix+'.tmp')
 try:
  with zipfile.ZipFile(temp,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as zf:
   for f in files:
    arc=f'{root.name}/{f.relative_to(root).as_posix()}'; info=zipfile.ZipInfo(arc,date_time=(2026,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED; info.create_system=3; info.external_attr=(stat.S_IFREG|0o644)<<16
    zf.writestr(info,f.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
  with zipfile.ZipFile(temp) as zf:
   bad=zf.testzip(); names=zf.namelist(); roots={PurePosixPath(n).parts[0] for n in names if PurePosixPath(n).parts}
   if bad: raise ValueError(f'Archive integrity failure at {bad}')
   if roots!={root.name}: raise ValueError(f'Unexpected ZIP roots: {sorted(roots)}')
   if any(PurePosixPath(n).is_absolute() or '..' in PurePosixPath(n).parts for n in names): raise ValueError('Unsafe path found in ZIP')
  temp.replace(output)
 finally:
  if temp.exists(): temp.unlink()
 return [f'{root.name}/{f.relative_to(root).as_posix()}' for f in files]
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent); p.add_argument('--output',type=Path); a=p.parse_args(argv)
 root=a.root.resolve(); out=a.output or root.parent/'dist'/f'{root.name}.zip'
 try: files=build(root,out)
 except (OSError,ValueError,zipfile.BadZipFile) as exc: print(f'FAIL: {exc}',file=sys.stderr); return 1
 print(f'PASS: built {out.resolve()}'); print(f'PASS: {len(files)} source files included'); print('PASS: archive opens, CRC test is clean, paths are relative and one top-level folder is present')
 print('Included key files:')
 for n in ('README.md','START_HERE.md','AGENTS.md','SKILL_ROUTER.md','MANIFEST.json'): print(f' - {root.name}/{n}')
 return 0
if __name__=='__main__': raise SystemExit(main())

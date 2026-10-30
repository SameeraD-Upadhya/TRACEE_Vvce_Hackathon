#!/usr/bin/env python3
# Copy the project-context template without overwriting by default.
from __future__ import annotations
import argparse, shutil, sys
from pathlib import Path

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('--target',type=Path,required=True); p.add_argument('--force',action='store_true',help='intentionally overwrite an existing target'); p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent)
 a=p.parse_args(argv); src=(a.root/'templates'/'project-context.md').resolve(); dst=a.target.expanduser().resolve()
 if not src.is_file(): print(f'ERROR: template not found: {src}',file=sys.stderr); return 2
 if dst==src or dst.is_dir(): print(f'ERROR: target must be a different file path, not a directory: {dst}',file=sys.stderr); return 2
 if dst.exists() and not a.force: print(f'ERROR: target already exists; refusing overwrite: {dst} (use --force intentionally)',file=sys.stderr); return 3
 try: dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,dst)
 except OSError as exc: print(f'ERROR: could not create context: {exc}',file=sys.stderr); return 4
 print(f'CREATED: {dst}'); print('Overwrote existing file.' if a.force else 'No existing file was overwritten.'); return 0
if __name__=='__main__': raise SystemExit(main())

# Unit tests for pack-validation behavior using isolated temporary directories.
from __future__ import annotations
import importlib.util, json, tempfile, unittest, zipfile
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'validate_pack.py'
spec=importlib.util.spec_from_file_location('validate_pack',SCRIPT); module=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(module)
validate_pack=module.validate_pack; validate_zip=module.validate_zip
class PackValidatorTests(unittest.TestCase):
 def make_pack(self,root):
  for d in module.REQUIRED_DIRS: (root/d).mkdir(parents=True,exist_ok=True)
  for rel in module.REQUIRED_FILES:
   (root/rel).parent.mkdir(parents=True,exist_ok=True); (root/rel).write_text('# fixture\n',encoding='utf-8')
  skill=root/'skills/core/demo/SKILL.md'; skill.parent.mkdir(parents=True,exist_ok=True)
  skill.write_text('---\nname: demo-skill\ndescription: A specific test capability.\ntriggers:\n  - fixture trigger\n---\n\n'+''.join(f'## {s}\nSubstantive fixture content.\n\n' for s in module.SECTIONS)+('Useful procedure and examples. '*100),encoding='utf-8')
  manifest={'name':'cybersecurity-vibecoding-skillpack','version':'1.0.0','purpose':'test','last_updated':'2026-10-25','compatibility_approach':'portable','categories':{'core':['skills/core/demo/SKILL.md'],'cybersecurity':[],'engineering':[]},'supported_modes':[],'utility_scripts':{},'safety_statement':'test','skills':['skills/core/demo/SKILL.md']}
  (root/'MANIFEST.json').write_text(json.dumps(manifest),encoding='utf-8')
 def test_missing_required_files_are_reported(self):
  with tempfile.TemporaryDirectory() as td:
   issues=validate_pack(Path(td)); self.assertTrue(any('Missing required file' in x for x in issues)); self.assertTrue(any('Missing required directory' in x for x in issues))
 def test_valid_skill_structure_has_no_skill_format_issues(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td); self.make_pack(root); issues=validate_pack(root); self.assertEqual([x for x in issues if x.startswith('skills/')],[])
 def test_invalid_skill_structure_is_detected(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td); self.make_pack(root); (root/'skills/core/demo/SKILL.md').write_text('# broken',encoding='utf-8'); issues=validate_pack(root)
   self.assertTrue(any('missing opening frontmatter' in x for x in issues)); self.assertTrue(any('missing section' in x for x in issues))
 def test_invalid_manifest_json_is_detected(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td); self.make_pack(root); (root/'MANIFEST.json').write_text('{invalid',encoding='utf-8'); self.assertTrue(any('MANIFEST.json invalid' in x for x in validate_pack(root)))
 def test_zip_root_and_required_content_are_checked(self):
  with tempfile.TemporaryDirectory() as td:
   z=Path(td)/'bad.zip'
   with zipfile.ZipFile(z,'w') as f: f.writestr('wrong-root/README.md','test')
   issues=validate_zip(z); self.assertTrue(any('top-level root' in x for x in issues)); self.assertTrue(any('ZIP missing required file' in x for x in issues))
if __name__=='__main__': unittest.main(verbosity=2)

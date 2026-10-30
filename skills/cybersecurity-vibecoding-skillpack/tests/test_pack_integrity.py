# Integrity tests for the checks added in 1.1.0. Each negative test corrupts a temporary copy of the real pack.
from __future__ import annotations
import importlib.util, json, shutil, tempfile, unittest, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
vp, bi, cp, bz = load('validate_pack'), load('build_index'), load('check_preservation'), load('build_zip')
SKILL = 'skills/cybersecurity/web-and-api-security/SKILL.md'
class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); self.copy = Path(self.td.name) / ROOT.name
        shutil.copytree(ROOT, self.copy, ignore=shutil.ignore_patterns('__pycache__'))
    def tearDown(self): self.td.cleanup()
    def issues(self): return vp.validate_pack(self.copy)
    def edit(self, rel, fn):
        p = self.copy / rel; p.write_text(fn(p.read_text(encoding='utf-8')), encoding='utf-8')
class IntegrityTests(Base):
    def test_real_pack_is_clean(self): self.assertEqual(self.issues(), [])
    def test_every_skill_has_manifest_index_and_router_coverage(self):
        m = json.loads((ROOT / 'MANIFEST.json').read_text()); self.assertEqual(len(m['skills']), len(list(ROOT.glob('skills/**/SKILL.md'))))
        self.assertEqual(bi.main(['--root', str(ROOT), '--check']), 0)
    def test_character_per_line_corruption_is_detected(self):
        self.edit(SKILL, lambda t: t.replace('## Procedure\n', '## Procedure\n1. D\n2. e\n3. f\n4. i\n', 1))
        self.assertTrue(any(x.startswith('Corrupted section') for x in self.issues()))
    def test_python_list_text_is_detected(self):
        self.edit(SKILL, lambda t: t + "\n['a rule', 'another rule']\n")
        self.assertTrue(any('Python list text' in x for x in self.issues()))
    def test_dangling_related_skill_is_detected(self):
        self.edit(SKILL, lambda t: t.replace('## Related Skills and Activation Triggers\n', '## Related Skills and Activation Triggers\nno-such-skill-here; ', 1))
        self.assertTrue(any('Unresolved related skill' in x and 'no-such-skill-here' in x for x in self.issues()))
    def test_dangling_router_reference_is_detected(self):
        self.edit('SKILL_ROUTER.md', lambda t: t + '\nUse `core/does-not-exist`.\n')
        self.assertTrue(any('Unresolved skill reference' in x for x in self.issues()))
    def test_index_drift_is_detected(self):
        self.edit('skills/INDEX.md', lambda t: '\n'.join(l for l in t.split('\n') if 'secrets-and-audit-logging' not in l))
        self.assertTrue(any(x.startswith('Index:') for x in self.issues())); self.assertEqual(bi.main(['--root', str(self.copy), '--check']), 1)
    def test_version_mismatch_is_detected(self):
        (self.copy / 'VERSION').write_text('9.9.9\n'); self.assertTrue(any(x.startswith('Version mismatch') for x in self.issues()))
    def test_boilerplate_duplication_is_detected(self):
        para = 'Shared filler paragraph that is deliberately long enough to exceed the duplication threshold used by the validator. ' * 3
        for rel in sorted(p.relative_to(self.copy).as_posix() for p in self.copy.glob('skills/**/SKILL.md'))[:7]:
            self.edit(rel, lambda t: t.replace('\n## Completion Checklist', '\n' + para + '\n\n## Completion Checklist', 1))
        self.assertTrue(any(x.startswith('Duplicated boilerplate') for x in self.issues()))
    def test_oversized_skill_is_detected(self):
        self.edit(SKILL, lambda t: t + ('\nextra words ' * 800)); self.assertTrue(any(x.startswith('Token budget') for x in self.issues()))
    def test_unlisted_template_is_detected(self):
        (self.copy / 'templates' / 'extra.md').write_text('# extra\n'); self.assertTrue(any('Manifest completeness' in x for x in self.issues()))
    def test_original_checks_still_catch_missing_manifest_skill(self):
        m = json.loads((self.copy / 'MANIFEST.json').read_text()); m['skills'].pop(); (self.copy / 'MANIFEST.json').write_text(json.dumps(m))
        self.assertTrue(any('MANIFEST skill list mismatch' in x for x in self.issues()))
class PreservationAndArchiveTests(Base):
    def test_identical_pack_passes_preservation(self): self.assertEqual(cp.main(['--original', str(ROOT), '--upgraded', str(self.copy)]), 0)
    def test_removed_file_fails_preservation(self):
        (self.copy / 'templates' / 'bug-report.md').unlink(); r = cp.compare(ROOT, self.copy); self.assertEqual(r['missing_files'], ['templates/bug-report.md'])
        self.assertEqual(cp.main(['--original', str(ROOT), '--upgraded', str(self.copy)]), 1)
    def test_renamed_skill_fails_preservation(self):
        self.edit(SKILL, lambda t: t.replace('name: web-and-api-security', 'name: web-security', 1)); self.assertTrue(cp.compare(ROOT, self.copy)['missing_skills'])
    def test_built_zip_validates_and_matches_source(self):
        out = Path(self.td.name) / 'out' / 'pack.zip'; names = bz.build(self.copy, out)
        self.assertEqual(vp.validate_zip(out), []); self.assertEqual(cp.compare(self.copy, out)['missing_files'], [])
        with zipfile.ZipFile(out) as zf: self.assertIsNone(zf.testzip()); self.assertEqual(len(zf.namelist()), len(names))
if __name__ == '__main__': unittest.main(verbosity=2)

"""Offline Ghost evidence smoke, mutation, and student ZIP separation tests."""
import csv,hashlib,sqlite3,subprocess,sys,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
A=ROOT/"artifacts"
class GhostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable,str(ROOT/"tools/build_lab.py")],check=True)
    def test_manifest_exact_file_set_and_hashes(self):
        lines=(A/"SHA256SUMS.txt").read_text().splitlines()
        named={}
        for line in lines:
            sha,name=line.split("  ",1)
            self.assertNotIn(name,named)
            named[name]=sha
        self.assertEqual(set(named),{p.name for p in A.iterdir() if p.is_file()}-{"SHA256SUMS.txt"})
        for name,digest in named.items():
            self.assertEqual(digest,hashlib.sha256((A/name).read_bytes()).hexdigest())
    def test_synthetic_hash_variance(self):
        self.assertNotEqual((A/"baseline_policy.bin").read_bytes(),(A/"observed_policy.bin").read_bytes())
    def test_real_sqlite_has_fk_trace(self):
        with sqlite3.connect(f"file:{(A/'timeline_cache.sqlite3').as_posix()}?mode=ro",uri=True) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM observations WHERE event_id='PROC-711'").fetchone()[0],1)
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0],"ok")
    def test_independent_origin_never_claimed(self):
        with (A/"acquisition_register.csv").open(newline="") as f:
            self.assertTrue(all(r["independently_verified"]=="no" for r in csv.DictReader(f)))
    def test_twenty_tasks_present(self):
        text=(ROOT/"questions/INVESTIGATION.md").read_text()
        for i in range(1,21):
            self.assertIn(f"**Q{i:02d}.**",text)
        self.assertNotIn("Answer key",text)
    def test_player_archive_is_complete_and_sealed(self):
        subprocess.run([sys.executable,str(ROOT/"tools/build_student_zip.py")],check=True)
        with zipfile.ZipFile(ROOT/"dist/The-Ghost-in-the-Kernel-STUDENT.zip") as z:
            self.assertIsNone(z.testzip())
            self.assertIn("artifacts/timeline_cache.sqlite3",z.namelist())
            self.assertIn("artifacts/SHA256SUMS.txt",z.namelist())
            self.assertIn("questions/INVESTIGATION.md",z.namelist())
            self.assertFalse(any(n.startswith("tools/") or n.startswith("tests/") or "instructor" in n.lower() for n in z.namelist()))
if __name__=="__main__":unittest.main()

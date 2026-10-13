#!/usr/bin/env python3
"""Build a deterministic student ZIP without instructor solutions."""
from __future__ import annotations
import hashlib
import sys
import zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
A=ROOT/"artifacts"
DEST=ROOT/"dist"/"The-Ghost-in-the-Kernel-STUDENT.zip"
PAGES=["README.txt","PLAYER-INSTRUCTIONS.md","questions/INVESTIGATION.md","docs/FORENSIC_SCOPE.md"]
def build():
    from verify_lab import verify
    verify()
    DEST.parent.mkdir(exist_ok=True)
    entries={n:(ROOT/n).read_bytes() for n in PAGES}
    entries.update({f"artifacts/{x.name}":x.read_bytes() for x in A.iterdir() if x.is_file()})
    assert len(entries)==len(PAGES)+len(list(A.iterdir()))
    with zipfile.ZipFile(DEST,"w") as z:
        for name in sorted(entries):
            info=zipfile.ZipInfo(name,(2026,9,17,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644<<16
            z.writestr(info,entries[name])
    with zipfile.ZipFile(DEST) as z:
        assert z.testzip() is None
        assert all(z.read(n)==content for n,content in entries.items())
        assert not any("/tools/" in n or "answer" in n.lower() or "walkthrough" in n.lower() or n.startswith("tools/") for n in z.namelist())
    print("PASS spoiler-free student archive:",DEST,len(entries),"entries")
if __name__=="__main__":
    try:build()
    except (OSError,ValueError,AssertionError) as e:print("FAIL",e,file=sys.stderr);sys.exit(1)

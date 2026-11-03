"""Deterministic release ZIP; Python is a build dependency, never a user dependency."""
import hashlib
import json
import pathlib
import sys
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
out = pathlib.Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
version = "0.2.0-rc.1"
paths = ["El Centinela de Windows.bat", "src/Centinela.ps1", "README.md", "LICENSE",
         "CHANGELOG.md", "docs/SECURITY-CANDIDATE.md", "schema.json", "llms.txt",
         "ai.txt", "robots.txt", "sitemap.xml", "assets/og-image.png"]
manifest = {}
archive = out / ("centinela-" + version + ".zip")
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name in sorted(paths):
        data = (root / name).read_bytes()
        manifest[name] = hashlib.sha256(data).hexdigest()
        info = zipfile.ZipInfo("centinela/" + name, (2026, 11, 2, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        z.writestr(info, data, compresslevel=9)
    z.writestr(zipfile.ZipInfo("centinela/MANIFEST.json", (2026, 11, 2, 0, 0, 0)),
               json.dumps({"version": version, "files": manifest}, sort_keys=True, indent=2).encode())
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for name, digest in manifest.items():
        assert hashlib.sha256(z.read("centinela/" + name)).hexdigest() == digest
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(out / "SHA256SUMS.txt").write_text(digest + "  " + archive.name + "\n", encoding="ascii")
print(json.dumps({"archive": str(archive), "sha256": digest, "files": len(paths)}))

"""Build a local NuGet package with two RID-specific managed assets."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


root = Path(__file__).resolve().parent
assembly = (root.parent / "dotnet-managed-assembly" / "Acme.Runtime.dll").read_bytes()
nuspec = b'''<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Acme.RidRuntime</id>
    <version>2.3.4</version>
    <authors>Ravel</authors>
    <description>Local RID-specific fixture</description>
  </metadata>
</package>
'''
feed = root / "feed"
feed.mkdir(exist_ok=True)
with ZipFile(feed / "Acme.RidRuntime.2.3.4.nupkg", "w") as archive:
    files = {
        "Acme.RidRuntime.nuspec": nuspec,
        "ref/net10.0/Acme.Runtime.dll": assembly,
        "runtimes/linux-x64/lib/net10.0/Acme.Runtime.dll": assembly,
        "runtimes/osx-arm64/lib/net10.0/Acme.Runtime.dll": assembly,
    }
    for name, data in sorted(files.items()):
        info = ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, data)

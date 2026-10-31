# Managed .NET assembly sample

This fixture was built from the included source with the .NET 10 SDK. The app
uses a local `Acme.Runtime` NuGet package, so regeneration needs no public
package feed. The published `.deps.json`, `app.dll`, and `Acme.Runtime.dll` are
checked in to exercise OCI file evidence without requiring `dotnet` in CI.

From this directory, regenerate the files with:

```sh
mkdir -p feed published
dotnet pack lib/Acme.Runtime.csproj -c Release -o feed -p:NuGetAudit=false
dotnet restore app/app.csproj --source "$(pwd)/feed" -p:NuGetAudit=false
dotnet publish app/app.csproj -c Release --no-restore -o published
cp published/app.deps.json published/app.dll published/Acme.Runtime.dll .
```

The package archive and `feed` directory are build outputs; the test uses the
published assembly and manifest files. The assembly hash in the test is
computed from the checked-in DLL, so different SDK build hashes are allowed.

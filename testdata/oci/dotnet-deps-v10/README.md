# .NET runtime dependency sample

`app.deps.json` was generated with the .NET 10 SDK by publishing the included
`app/app.csproj` project. It contains one root application, a project reference,
and six NuGet packages with runtime assets and transitive dependency links.

To regenerate it with the .NET 10 SDK:

```sh
dotnet publish app/app.csproj -c Release -o published -p:NuGetAudit=false
cp published/app.deps.json app.deps.json
```

The test embeds this manifest in an OCI image layer. It does not bundle or
assert the presence of the published assemblies.

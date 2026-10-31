# Legacy .NET dependency manifest case

`legacy.deps.json` is a hand-authored .NET 8 style runtime manifest used to
exercise a format behavior that the .NET 10 SDK no longer generates by default:
libraries without runtime assets can remain in the selected target.

The case has a compile-only analyzer, an unused metadata package, and a
metadata package that connects the root project to a library with a runtime
assembly. Only the latter metadata package belongs to the runtime dependency
path represented in the SBOM.

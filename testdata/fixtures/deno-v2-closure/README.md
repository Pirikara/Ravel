# Deno lockfile version 2

This original fixture reduces the legacy npm layout used by Pyodide's Deno
tests. A runtime source import selects one npm root and its renamed dependency;
the unused locked package stays outside the selected closure. Version 2 nests
specifiers and dependency maps under `npm` and predates JSR.

package nuget

import "testing"

func TestRuntimeAssemblyCandidatesScopeAndPathSafety(t *testing.T) {
	data := []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"App/1.0.0":{"runtime":{"App.dll":{},"../outside.dll":{},"lib/net10.0/Good.dll":{"assemblyVersion":"1.0.0.0"},"lib/net10.0/Bad.dll":"wrong","runtimes\\win\\Unsafe.dll":{}},"runtimeTargets":{"runtimes/linux-x64/lib/net10.0/Rid.dll":{"rid":"linux-x64","assetType":"runtime"},"runtimes/linux-x64/native/Native.dll":{"rid":"linux-x64","assetType":"native"},"runtimes/linux-x64/lib/net10.0/Wrong.dll":{"rid":"osx-arm64","assetType":"runtime"}}}},"other":{"Wrong/1.0.0":{"runtime":{"Wrong.dll":{}}}}},"libraries":{"App/1.0.0":{"type":"project"}}}`)
	candidates := RuntimeAssemblyCandidates(data, "app/App.deps.json")
	actual := candidates["app/1.0.0"]
	if len(actual) != 3 || actual[0] != (RuntimeAssemblyCandidate{Path: "app/App.dll"}) || actual[1] != (RuntimeAssemblyCandidate{Path: "app/Good.dll"}) || actual[2] != (RuntimeAssemblyCandidate{Path: "app/runtimes/linux-x64/lib/net10.0/Rid.dll", RID: "linux-x64"}) || len(candidates) != 1 {
		t.Fatalf("unsafe or non-active .NET assembly candidate: %#v", candidates)
	}
}

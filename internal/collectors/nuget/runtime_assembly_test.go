package nuget

import "testing"

func TestRuntimeAssemblyCandidatesScopeAndPathSafety(t *testing.T) {
	data := []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"App/1.0.0":{"runtime":{"App.dll":{},"../outside.dll":{},"lib/net10.0/Good.dll":{"assemblyVersion":"1.0.0.0"},"lib/net10.0/Bad.dll":"wrong","runtimes\\win\\Unsafe.dll":{}}}},"other":{"Wrong/1.0.0":{"runtime":{"Wrong.dll":{}}}}},"libraries":{"App/1.0.0":{"type":"project"}}}`)
	candidates := RuntimeAssemblyCandidates(data, "app/App.deps.json")
	actual := candidates["app/1.0.0"]
	if len(actual) != 2 || actual[0] != "app/App.dll" || actual[1] != "app/Good.dll" || len(candidates) != 1 {
		t.Fatalf("unsafe or non-active .NET assembly candidate: %#v", candidates)
	}
}

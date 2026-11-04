package model

type Evidence struct {
	Collector   string `json:"collector"`
	InputPath   string `json:"inputPath"`
	InputDigest string `json:"inputDigest"`
	Line        int    `json:"line"`
	Pointer     string `json:"pointer,omitempty"`
	Method      string `json:"method"`
	ObservedAt  string `json:"observedAt,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type Component struct {
	ID       string     `json:"id"`
	Kind     string     `json:"kind"`
	Name     string     `json:"name"`
	Version  string     `json:"version"`
	Platform string     `json:"platform,omitempty"`
	Context  string     `json:"context,omitempty"`
	PURL     string     `json:"purl,omitempty"`
	Hashes   []Hash     `json:"hashes,omitempty"`
	Patches  []Patch    `json:"patches,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

// Patch describes a project-local modification declared for a package. Hashes
// on the component continue to describe the unmodified distribution artifact.
type Patch struct {
	Path     string     `json:"path,omitempty"`
	Hash     *Hash      `json:"hash,omitempty"`
	Status   string     `json:"status"`
	Evidence []Evidence `json:"evidence"`
}

type Edge struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Kind      string   `json:"kind"`
	Condition string   `json:"condition,omitempty"`
	Evidence  Evidence `json:"evidence"`
}

type Origin struct {
	Occurrence string   `json:"occurrence"`
	Kind       string   `json:"kind"`
	SafeURL    string   `json:"safeUrl"`
	LocalPath  string   `json:"localPath,omitempty"`
	Target     string   `json:"target,omitempty"`
	Revision   string   `json:"revision,omitempty"`
	Status     string   `json:"status"`
	Evidence   Evidence `json:"evidence"`
}

type Development struct {
	Occurrence string   `json:"occurrence"`
	SafeURL    string   `json:"safeUrl"`
	Status     string   `json:"status"`
	Evidence   Evidence `json:"evidence"`
}

// RuntimeRequirement is a repository declaration. It does not claim that the
// runtime is installed in the scanned checkout or in a deployment image.
type RuntimeRequirement struct {
	Name        string   `json:"name"`
	Requirement string   `json:"requirement"`
	Relation    string   `json:"relation"`
	Scope       string   `json:"scope"`
	Policy      string   `json:"policy,omitempty"`
	Evidence    Evidence `json:"evidence"`
}

type Issue struct {
	Code  string `json:"code"`
	Name  string `json:"name,omitempty"`
	Line  int    `json:"line,omitempty"`
	Scope string `json:"scope,omitempty"`
}

type InputCoverage struct {
	Project     string  `json:"project"`
	Source      string  `json:"source"`
	Manager     string  `json:"manager"`
	GraphState  string  `json:"graphState"`
	OriginState string  `json:"originState"`
	Packages    int     `json:"packages"`
	Edges       int     `json:"edges"`
	Issues      []Issue `json:"issues"`
}

type Coverage struct {
	Manager     string          `json:"manager"`
	GraphState  string          `json:"graphState"`
	OriginState string          `json:"originState"`
	Platforms   []string        `json:"platforms,omitempty"`
	Packages    int             `json:"packages"`
	Edges       int             `json:"edges"`
	Issues      []Issue         `json:"issues"`
	Inputs      []InputCoverage `json:"inputs,omitempty"`
}

type Document struct {
	SchemaVersion string               `json:"schemaVersion"`
	Project       string               `json:"project"`
	Source        string               `json:"source"`
	Sources       []string             `json:"sources,omitempty"`
	Components    []Component          `json:"components"`
	Edges         []Edge               `json:"edges"`
	Origins       []Origin             `json:"origins"`
	Development   []Development        `json:"development"`
	Runtimes      []RuntimeRequirement `json:"runtimes,omitempty"`
	Coverage      Coverage             `json:"coverage"`
}

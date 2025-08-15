//Declares the module name as "waf-engine", which is the import path for this project.
module waf-engine

// Specifies the Go language version used for this project.
// Ensures compatibility with features and syntax introduced in Go 1.24.5.
go 1.24.5

// Adds YAML parsing support using the gopkg.in/yaml.v3 library.
// The "// indirect" comment means this dependency is used by some other package in your project,
// not directly by your own code, but Go tracks it to ensure reproducible builds.
require gopkg.in/yaml.v3 v3.0.1 // indirect

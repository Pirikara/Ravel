module example.com/SourceApp

go 1.25

require (
	example.com/Acme/Lib v1.0.0
	example.net/library v1.0.0
	example.com/LOCAL v1.0.0
	example.com/Fork v1.0.0
)

replace example.com/LOCAL => ./local
replace example.com/Fork => fork.example/Actual v1.1.0

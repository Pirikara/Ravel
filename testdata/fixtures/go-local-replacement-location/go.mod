module example.com/source-app

go 1.25

require (
 example.com/local v1.0.0
 example.com/fork v1.2.0
 example.com/indirect v1.0.0 // indirect
)

replace example.com/local => "./local modules/component"
replace example.com/fork v1.2.0 => fork.example/component v1.3.0

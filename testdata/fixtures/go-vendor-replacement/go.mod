module example.com/app

go 1.23

require github.com/acme/alpha v1.2.3

replace github.com/acme/alpha => example.com/forks/alpha v1.2.4

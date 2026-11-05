require_relative "lib/example/version"

Gem::Specification.new do |spec|
  spec.name = "example"
  spec.version = Example::VERSION
  spec.add_dependency "child", ">= 1.0"
end

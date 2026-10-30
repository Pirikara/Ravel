Gem::Specification.new do |spec|
  spec.name = "ravel-archive-sample"
  spec.version = "1.2.3"
  spec.summary = "Ravel Ruby archive fixture"
  spec.authors = ["Ravel"]
  spec.files = ["lib/ravel_archive_sample.rb"]
  spec.metadata = {
    "source_code_uri" => "https://builder:example-secret@github.com/ravel/ruby-archive.git?token=private",
  }
  spec.add_runtime_dependency "rack", "~> 3.1"
end

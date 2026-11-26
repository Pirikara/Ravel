# Reduced, original regression for literal metadata alongside computed fields.
spec = Gem::Specification.new do |s|
  s.name = 'mixed-source'
  s.version = '1.2.3'
  s.homepage = 'https://docs.example.test/mixed-source'
  s.metadata = {
    'changelog_uri' => "https://code.example.test/releases/v#{s.version}",
    'homepage_uri' => s.homepage,
    'source_code_uri' => 'https://code.example.test/mixed-source',
  }
end

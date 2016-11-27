MRuby::Gem::Specification.new('mruby-libiptc') do |spec|
  spec.name = 'mruby-libiptc'
  spec.authors = ['Kohei Suzuki']
  spec.licenses = ['MIT']

  spec.linker.libraries << 'ip4tc' << 'ip6tc'
end

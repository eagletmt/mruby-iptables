MRuby::Gem::Specification.new('mruby-iptables') do |spec|
  spec.name = 'mruby-iptables'
  spec.authors = ['Kohei Suzuki']
  spec.licenses = ['MIT']

  spec.linker.libraries << 'ip4tc' << 'ip6tc' << 'xtables'
end

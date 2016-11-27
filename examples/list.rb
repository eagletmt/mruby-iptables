[Libip4tc::Handle, Libip6tc::Handle].each do |handle_class|
  puts handle_class
  %w[filter nat].each do |table|
    puts "  #{table}"
    h = handle_class.new(table)
    chain = h.first_chain
    while chain
      policy = h.get_policy(chain)
      puts "    #{chain}#{h.builtin?(chain) ? ' (builtin)' : ''} (policy #{policy.inspect})"
      rule = h.first_rule(chain)
      while rule
        puts "      #{rule.get_target(h)} #{rule.inspect}"
        rule = h.next_rule(rule)
      end
      chain = h.next_chain
    end
  end
end

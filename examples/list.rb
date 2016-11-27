[Libip4tc::Handle, Libip6tc::Handle].each do |handle_class|
  puts handle_class
  %w[filter nat].each do |table|
    puts "  #{table}"
    h = handle_class.new(table)
    chain = h.first_chain
    while chain
      puts "    #{chain}"
      rule = h.first_rule(chain)
      while rule
        puts "      #{rule.inspect}"
        rule = h.next_rule(rule)
      end
      chain = h.next_chain
    end
  end
end

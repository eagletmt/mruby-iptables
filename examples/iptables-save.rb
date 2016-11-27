def rule_to_args(rule)
  args = []

  if rule.src != '0.0.0.0/0' && rule.src != '::/0'
    args << '-s' << rule.src
  end
  if rule.dst != '0.0.0.0/0' && rule.dst != '::/0'
    args << '-d' << rule.dst
  end


  if rule.iniface
    if rule.inv_via_in?
      args << '!'
    end
    args << '-i' << rule.iniface
  end
  if rule.outiface
    if rule.inv_via_out?
      args << '!'
    end
    args << '-o' << rule.outiface
  end

  if rule.proto
    if rule.inv_proto?
      args << '!'
    end
    args << '-p' << rule.proto
  end

  rule.matches.each do |m|
    args << '-m' << m.name << m.args
  end

  args
end

{
  iptables: Libip4tc::Handle,
  ip6tables: Libip6tc::Handle,
}.each do |ipt, handle_class|
  %w[nat filter].each do |table|
    puts "*#{table}"
    h = handle_class.new(table)

    chain = h.first_chain
    while chain
      print ":#{chain} "
      if h.builtin?(chain)
        policy = h.get_policy(chain)
        puts "#{policy.name} [#{policy.pcnt}:#{policy.bcnt}]"
      else
        puts '- [0:0]'
      end
      chain = h.next_chain
    end

    chain = h.first_chain
    while chain
      rule = h.first_rule(chain)
      while rule
        puts ['-A', chain, *rule_to_args(rule), '-j', rule.get_target(h)].join(' ')
        rule = h.next_rule(rule)
      end
      chain = h.next_chain
    end
    puts 'COMMIT'
  end
end

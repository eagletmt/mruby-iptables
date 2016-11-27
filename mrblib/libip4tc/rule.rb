module Libip4tc
  class Rule
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} pcnt=#{pcnt} bcnt=#{bcnt} src=#{src.inspect} dst=#{dst.inspect} iniface=#{iniface.inspect} outiface=#{outiface.inspect}>"
    end
  end
end

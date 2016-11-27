module Libip6tc
  class Rule
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} pcnt=#{pcnt} bcnt=#{bcnt} src=#{src} dst=#{dst}>"
    end
  end
end

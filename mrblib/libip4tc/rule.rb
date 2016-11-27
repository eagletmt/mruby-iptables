module Libip4tc
  class Rule
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} pcnt=#{pcnt} bcnt=#{bcnt} src=#{src.inspect} dst=#{dst.inspect} iniface=#{iniface.inspect} outiface=#{outiface.inspect} frag?=#{frag?} goto?=#{goto?} inv_via_in?=#{inv_via_in?} inv_via_out?=#{inv_via_out?} inv_tos?=#{inv_tos?} inv_srcip?=#{inv_srcip?} inv_dstip?=#{inv_dstip?} inv_frag?=#{inv_frag?} inv_proto?=#{inv_proto?}>"
    end
  end
end

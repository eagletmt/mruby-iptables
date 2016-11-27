module Libip4tc
  class Policy
    attr_reader :name, :pcnt, :bcnt

    def initialize(name, pcnt, bcnt)
      @name = name
      @pcnt = pcnt
      @bcnt = bcnt
    end
  end
end

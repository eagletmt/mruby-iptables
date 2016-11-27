module Libip4tc
  class Match
    attr_reader :name, :args

    def initialize(name, args)
      @name = name
      @args = args
    end
  end
end

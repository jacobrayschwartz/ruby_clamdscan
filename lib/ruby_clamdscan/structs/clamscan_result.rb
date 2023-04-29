# frozen_string_literal: true

require "dry-types"
require "dry-struct"

# Importing dry types
module Types
  include Dry.Types
end

module RubyClamdscan
  module Structs
    # Represents the result from scanning a file with ClamAV
    class ClamscanResult < Dry::Struct
      # If the command successfully - does not indicate file was safe! Check contains_virus for that information
      attribute :is_successful, Types::Bool

      # If ClamAV detected malware in the
      attribute :contains_virus, Types::Bool

      # Returns the error string if the command failed
      attribute :error, Types::Strict::String.optional.default(nil)

      # Returns virus information if a virus was detected
      attribute :virus_info, Types::Strict::String.optional.default(nil)
    end
  end
end

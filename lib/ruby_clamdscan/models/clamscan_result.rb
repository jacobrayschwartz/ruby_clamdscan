# frozen_string_literal: true

module RubyClamdscan
  module Models
    # Represents the result from scanning a file with ClamAV
    class ClamscanResult
      # If the command successfully - does not indicate file was safe! Check contains_virus for that information
      # @return [Boolean]
      attr_reader :is_successful

      # If ClamAV detected malware in the passed file
      # @return [Boolean]
      attr_reader :contains_virus

      # Returns the error string if the command failed
      # @return [Exception, nil]
      attr_reader :error

      # Returns virus information if a virus was detected
      # Value is the response from ClamAV, the malware classification - should be in the form of "Win.Test.EICAR_HDB-1"
      # @return [String, nil]
      attr_reader :virus_info

      def initialize(is_successful:, contains_virus:, virus_info: nil, error: nil)
        @is_successful = is_successful
        @contains_virus = contains_virus
        @error = error
        @virus_info = virus_info
      end
    end
  end
end

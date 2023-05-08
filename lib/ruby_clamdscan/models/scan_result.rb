# frozen_string_literal: true

module RubyClamdscan
  module Models
    # Represents the result from scanning a file with ClamAV
    class ScanResult
      # If the command successfully - does not indicate file was safe! Check contains_virus for that information
      # @return [Boolean]
      attr_reader :is_successful

      # If ClamAV detected malware in the passed file, will be nil if there was an error running the command
      # @return [Boolean, nil]
      attr_reader :contains_virus

      # Returns the error string if the command failed
      # @return [Exception, nil]
      attr_reader :exception

      # Returns the error string if the command failed
      # @return [String, nil]
      attr_reader :error_message

      # Returns virus information if a virus was detected
      # Value is the response from ClamAV, the malware classification - should be in the form of "Win.Test.EICAR_HDB-1"
      # @return [String, nil]
      attr_reader :virus_info

      def initialize(is_successful:, contains_virus:, virus_info: nil, exception: nil, error_message: nil)
        @is_successful = is_successful
        @contains_virus = contains_virus
        @exception = exception
        @error_message = error_message
        @virus_info = virus_info
      end
    end

    class StatsResult
      attr_reader :total_pools, :state, :threads_live, :threads_idle, :threads_max
    end
  end
end

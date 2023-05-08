# frozen_string_literal: true

require "ruby_clamdscan/commands/utils"

module RubyClamdscan
  module Commands
    # Status commands for ClamAV
    module Status
      # Attempts to ping the ClamAV server
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      # @raise [RubyClamdscan::Exceptions::EmptyResponseError] If server response is empty
      def self.ping_server(configuration)
        RubyClamdscan::Commands::Utils.send_single_command("PING", configuration)
      end

      # Attempts to retrieve the ClamAV server's version information
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      # @raise [RubyClamdscan::Exceptions::EmptyResponseError] If server response is empty
      def self.server_version(configuration)
        RubyClamdscan::Commands::Utils.send_single_command("VERSION", configuration)
      end

      # Replies with statistics about the scan queue, contents of scan queue, and memory usage
      # Because the format of this response is subject to change, this method will only return the string
      # Uses "nSTATS\n", blocks in the returned response will be separated by the \n character
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      # @return [String] Format (currently):
      # "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 10 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000375 \n\n
      # MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 1281.773M pools_total 1281.827M\nEND"
      # @raise [RubyClamdscan::Errors::EmptyResponseError] If server response is empty
      def self.server_stats(configuration)
        RubyClamdscan::Commands::Utils.send_single_command("nSTATS\n", configuration)
      end
    end
  end
end

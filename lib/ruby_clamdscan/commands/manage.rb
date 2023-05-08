# frozen_string_literal: true

require "ruby_clamdscan/commands/utils"

module RubyClamdscan
  module Commands
    # Management commands for ClamAV server
    module Manage
      # Force ClamAV to reload the virus databases
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      # @return [String] "RELOADING"
      # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
      # @raise [RubyClamdscan::Errors::EmptyResponseError] If server response is empty
      def self.reload_server_database(configuration)
        RubyClamdscan::Commands::Utils.send_single_command("RELOAD", configuration)
      end

      # Shutdown ClamAV server
      # Note: this will completely close socket communication. Server cannot be restarted through this library
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
      # @return [Boolean] true if shutdown command was sent
      def self.shutdown_server(configuration)
        true if RubyClamdscan::Commands::Utils.send_single_command("SHUTDOWN", configuration, ignore_empty_response: true)
        false
      end
    end
  end
end

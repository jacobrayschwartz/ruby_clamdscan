# frozen_string_literal: true

require "ruby_clamdscan/commands/utils"

module RubyClamdscan
  module Commands
    # Management commands for
    module Manage
      # Force ClamAV to reload the virus databases
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      def self.reload_server_database(configuration)
        RubyClamdscan::Commands::Utils.send_single_command("RELOAD", configuration)
      end

      # Shutdown ClamAV server
      # Note: this will completely close socket communication. Server cannot be restarted through this library
      # @param configuration [RubyClamdscan::Configuration] configuration for building the ClamAV connection
      def self.shutdown_server(configuration)
        RubyClamdscan::Commands::Utils.send_single_command("SHUTDOWN", configuration)
      end
    end
  end
end

# frozen_string_literal: true

require "ruby_clamdscan/errors/clamav_errors"

module RubyClamdscan
  module Commands
    # Utilities for running commands
    module Utils
      # Sends a single command to the ClamAV server and return its response
      # @param command [String] Command to send
      # @param configuration [RubyClamdscan::Configuration] Configuration used for building socket
      # @return [String] Response from ClamAV server
      # @raise [RubyClamdscan::Errors::EmptyResponseError] if configuration.raise_error_on_empty_response is true and server doesn't send response
      # @raise
      def self.send_single_command(command, configuration, ignore_empty_response: false)
        response = ""
        begin
          clam_av_stream = RubyClamdscan::Socket.open_clamav_socket(configuration)
          clam_av_stream.write(command)
          clam_av_stream.flush

          while (data = clam_av_stream.gets)
            response += data
          end

          response = response.strip
        rescue StandardError => e
          raise RubyClamdscan::Errors::ClamAVCommunicationError.new(command, e)
        ensure
          clam_av_stream&.close
        end

        if !ignore_empty_response && configuration.raise_error_on_empty_response && response.empty?
          raise RubyClamdscan::Errors::EmptyResponseError,
                command
        end

        response
      end
    end
  end
end

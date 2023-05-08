# frozen_string_literal: true

module RubyClamdscan
  module Errors
    # Raised when ClamAV returns an empty response - usually means that the server has not finished starting or is shutdown
    class EmptyResponseError < StandardError
      # @param command [String] Command that failed
      # @param msg [String, nil] Optional message
      def initialize(command, msg: nil)
        msg = "Got empty response when attempting to run command: #{command}. Are you sure the ClamAV server is running?" unless msg.nil?
        super(msg)
      end
    end

    # Raised when there is some error in communicating with the ClamAV server
    # @param command [String] Command that failed
    # @param cause [StandardError, nil] Underlying error if found
    # @param msg [String, nil] Optional message
    class ClamAVCommunicationError < StandardError
      # @return [StandardError, nil] Underlying error if found
      attr_reader :cause

      def initialize(command, cause, msg: nil)
        @cause = cause
        msg = "Error while communicating with ClamAV - cause: #{cause&.msg} command: #{command}." unless msg.nil?
        super(msg)
      end
    end

    # Raised if ClamAV detects malware in the scanned contents
    class VirusDetectedError < StandardError
      # @return [RubyClamdscan::Models::ScanResult] Information about scan and virus
      attr_reader :scan_result

      # @param scan_result [RubyClamdscan::Models::ScanResult] Information about scan result
      # @param msg [String, nil] Optional message
      def initialize(scan_result, msg: nil)
        @scan_result = scan_result
        msg = "Detected malware in scanned contents: #{scan_result.virus_info}" unless msg.nil?
        super(msg)
      end
    end
  end
end

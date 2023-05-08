# frozen_string_literal: true

require "socket"
require "ruby_clamdscan/models/scan_result"
require "ruby_clamdscan/errors/clamav_errors"

module RubyClamdscan
  module Commands
    # Methods for scanning file contents
    module Scan
      SCAN_COMMAND = "zINSTREAM\0"

      # Stream file contents to ClamAV
      # @param file_input_stream [IO] Input file_input_stream to scan
      # @param configuration [RubyClamdscan::Configuration] Configuration settings
      # @return [RubyClamdscan::Models::ScanResult]
      # @raise [RubyClamdscan::Errors::VirusDetectedError] if Configuration is set to raise exception and malware is detected
      # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
      def self.scan(file_input_stream, configuration)
        response = ""
        clam_av_stream = nil

        begin
          clam_av_stream = RubyClamdscan::Socket.open_clamav_socket(configuration)
          send_contents(clam_av_stream, configuration, file_input_stream)
          response = get_response(clam_av_stream)
        rescue StandardError => e
          raise RubyClamdscan::Errors::ClamAVCommunicationError.new(SCAN_COMMAND, e)
        ensure
          clam_av_stream&.close
        end

        result = build_result(response)

        raise RubyClamdscan::Errors::VirusDetectedError, result if configuration.raise_error_on_virus_detected && result.contains_virus

        result
      end

      # Stream file contents to ClamAV
      # @param filepath [String] Path to file in local storage to scan
      # @param configuration [RubyClamdscan::Configuration] Configuration settings
      # @return [RubyClamdscan::Models::ScanResult]
      # @raise IOError if there is no file found at filepath
      def self.scan_file(filepath, configuration)
        raise IOError, "Unable to find file #{filepath}" unless File.exist?(filepath)

        begin
          fd = IO.sysopen(filepath, "rb")
          fin = IO.new(fd)
          result = scan(fin, configuration)
        ensure
          fin.close
        end
        result
      end

      # Builds a result object after parsing the response from ClamAV
      # @param response [String] Response from ClamAV stream
      # @return [RubyClamdscan::Models::ScanResult] Constructed result object
      def self.build_result(response)
        # OK response: "stream: OK"
        # Malware response: "stream: Win.Test.EICAR_HDB-1 FOUND"
        # Error response "stream: <message> ERROR"

        response = response.strip # Strip out any trailing empty chars from the buffer
        tokens = response.split(" ")
        puts("RESPONSE:'#{response}'")

        case tokens
        in ["stream:", "OK"]
          RubyClamdscan::Models::ScanResult.new(is_successful: true, contains_virus: false)
        in ["stream:", virus_info, "FOUND"]
          RubyClamdscan::Models::ScanResult.new(is_successful: true, contains_virus: true, virus_info:)
        in []
          RubyClamdscan::Models::ScanResult.new(is_successful: false, contains_virus: nil,
                                                error_message: "Empty response from ClamAV, is the server accepting connections?")
        else
          RubyClamdscan::Models::ScanResult.new(is_successful: false, contains_virus: nil, error_message: response)
        end
      end

      private_class_method :build_result

      # Gets the response from ClamAV off the stream
      # @param clam_av_stream [IO] Read stream from ClamAV
      # @return [String] Response
      def self.get_response(clam_av_stream)
        response = ""
        while (data = clam_av_stream.gets)
          response += data
        end
        response
      end

      private_class_method :get_response

      # Sends file contents from stream to ClamAV
      # @param clam_av_stream [IO] Stream to ClamAV
      # @param configuration [RubyClamdscan::Configuration] Params defining how much data to send per chunk
      # @param file_input_stream [IO] Stream to read file contents from
      def self.send_contents(clam_av_stream, configuration, file_input_stream)
        clam_av_stream.write(SCAN_COMMAND) # Write the command to tell ClamAV to start scanning
        clam_av_stream.flush
        while (chunk = file_input_stream.read(configuration.chunk_size))
          chunk_len = [chunk.length].pack("N")
          clam_av_stream.write(chunk_len + chunk)
          clam_av_stream.flush
        end
        clam_av_stream.write([0x00, 0x00, 0x00, 0x00].pack("NNNN"))
        clam_av_stream.flush
      end

      private_class_method :send_contents
    end
  end
end

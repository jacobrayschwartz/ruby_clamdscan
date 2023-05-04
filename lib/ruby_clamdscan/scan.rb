# frozen_string_literal: true

require "socket"
require "ruby_clamdscan/models/clamscan_result"

module RubyClamdscan
  # Methods for scanning filecontents
  module Scan
    # Stream file contents to ClamAV
    # @param file_input_stream [IO] Input file_input_stream to scan
    # @param clam_av_stream [IO] Connection to ClamAV service
    # @param configuration [RubyClamdscan::Configuration] Configuration settings
    # @return [RubyClamdscan::Models::ClamscanResult]
    def self.scan(file_input_stream, clam_av_stream, configuration)
      response = ""

      begin
        clam_av_stream.write("zINSTREAM\0") # Write the command to tell ClamAV to start scanning
        clam_av_stream.flush
        while (chunk = file_input_stream.read(configuration.chunk_size))
          # puts chunk
          # puts chunk.length
          chunk_len = [chunk.length].pack("N")
          clam_av_stream.write(chunk_len + chunk)
          clam_av_stream.flush
        end
        clam_av_stream.write([0x00, 0x00, 0x00, 0x00].pack("NNNN"))
        clam_av_stream.flush

        while (data = clam_av_stream.gets)
          response += data
        end
      ensure
        clam_av_stream.close
      end

      build_result(response)
    end

    # Stream file contents to ClamAV
    # @param file_input_stream [IO] Input file_input_stream to scan
    # @param filepath [String] Path to file in local storage to scan
    # @param configuration [RubyClamdscan::Configuration] Configuration settings
    # @return [RubyClamdscan::Models::ClamscanResult]
    def self.scan_file(filepath, clam_av_stream, configuration)
      begin
        fd = IO.sysopen(filepath, "rb")
        fin = IO.new(fd)
        result = scan(fin, clam_av_stream, configuration)
      ensure
        fin.close
      end
      result
    end

    # Builds a result object after parsing the response from ClamAV
    # @param response [String] Response from ClamAV stream
    # @return [RubyClamdscan::Models::ClamscanResult] Constructed result object
    def self.build_result(response)
      # OK response: "stream: OK"
      # Malware response: "stream: Win.Test.EICAR_HDB-1 FOUND"
      # Error response "stream: <message> ERROR"

      response = response.strip # Strip out any trailing empty chars from the buffer
      tokens = response.split(" ")

      case tokens
      in ["stream:", "OK"]
        RubyClamdscan::Models::ClamscanResult.new(is_successful: true, contains_virus: false)
      in ["stream:", virus_info, "FOUND"]
        RubyClamdscan::Models::ClamscanResult.new(is_successful: true, contains_virus: true, virus_info:)
      else
        RubyClamdscan::Models::ClamscanResult.new(is_successful: false, contains_virus: false, error: response)
      end
    end

    private_class_method :build_result
  end
end

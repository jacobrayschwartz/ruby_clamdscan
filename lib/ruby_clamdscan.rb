# frozen_string_literal: true

require "ruby_clamdscan/socket"
require "ruby_clamdscan/scan"
require "ruby_clamdscan/configuration"
require "ruby_clamdscan/version"

# Utility for interacting with ClamAV
module RubyClamdscan
  class << self
    # Configuration to use interacting with the ClamAV server
    def configuration
      @configuration ||= Configuration.new
      @configuration.use_tcp_socket = true
      @configuration.tcp_host = "localhost"
      @configuration.tcp_port = 3310

      @configuration
    end

    # Configure RubyClamdscan
    def configure
      yield(configuration)
    end

    # Scans a file
    # @param filepath [String] Path to file in local storage
    # @return [RubyClamdscan::Models::ClamscanResult] Result from the scan attempt
    def scan_file_from_path(filepath)
      RubyClamdscan::Scan.scan_file(filepath, @configuration)
    end

    # Scans the contents of the stream passed in
    # @param stream [IO] stream of file contents
    # @return [RubyClamdscan::Models::ClamscanResult] Result from the scan attempt
    def scan_contents(stream)
      RubyClamdscan::Scan.scan(stream, @configuration)
    end
  end
end

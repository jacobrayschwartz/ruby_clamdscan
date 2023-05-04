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

    def scan_file_from_path(filepath)
      socket = RubyClamdscan::Socket.open_clamav_socket(@configuration)
      RubyClamdscan::Scan.scan_file(filepath, socket, @configuration)
    end

    # Scans the contents of the stream passed in
    # @param stream [IO] stream of file contents
    def scan_contents(stream)
      socket = RubyClamdscan::Socket.open_clamav_socket(@configuration)
      RubyClamdscan::Scan.scan(stream, socket, @configuration)
    end
  end
end

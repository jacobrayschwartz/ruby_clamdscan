# frozen_string_literal: true

module RubyClamdscan
  # Configuration for the gem
  class Configuration
    # TCP Port ClamAV is listening on if using TCP
    # Default: 3310
    # @return [Integer]
    attr_accessor :tcp_port

    # Host ClamAV is listening on if using TCP
    # Default: localhost
    # @return [String]
    attr_accessor :tcp_host

    # Unix Socket for ClamAV
    # Default: /tmp/clamd.socket
    # @return [String]
    attr_accessor :unix_socket

    # Chunk size in bytes for streaming files
    # Default: 1024
    # @return [Integer]
    attr_accessor :chunk_size

    # If TCP socket should be used. If false, the Unix socket will be used instead
    # Note, if running ClamAV on the same host, it is recommended to use the Unix socket as it's much faster
    # Default: false
    # @return [Boolean]
    attr_accessor :use_tcp_socket

    def initialize
      @tcp_host = "localhost"
      @tcp_port = 3310
      @chunk_size = 1024
      @unix_socket = "/tmp/clamd.socket"
    end
  end
end

# frozen_string_literal: true

require "socket"

module RubyClamdscan
  # Socket related methods to open communication
  module Socket
    # Open a socket to ClamAV based on RubyClamdscan.Configuration
    # @return [IO]
    def self.open_clamav_socket
      if RubyClamdscan.configuration.use_tcp_socket
        open_tcp_socket
      else
        open_unix_socket
      end
    end

    def self.open_tcp_socket
      TCPSocket.open(RubyClamdscan.configuration.tcp_host, RubyClamdscan.configuration.tcp_port)
    end

    private_class_method :open_tcp_socket

    def self.open_unix_socket
      UNIXSocket.new(RubyClamdscan.configuration.unix_socket)
    end

    private_class_method :open_unix_socket
  end
end

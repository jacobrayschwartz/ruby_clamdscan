# frozen_string_literal: true

require "socket"

module RubyClamdscan
  # Socket related methods to open communication
  module Socket
    # Open a socket to ClamAV based on RubyClamdscan.Configuration
    # @param configuration [RubyClamdscan::Configuration] configuration used to determine socket
    # @return [IO]
    def self.open_clamav_socket(configuration)
      if configuration.use_tcp_socket
        open_tcp_socket(configuration)
      else
        open_unix_socket(configuration)
      end
    end

    def self.open_tcp_socket(configuration)
      TCPSocket.open(configuration.tcp_host, configuration.tcp_port)
    end

    private_class_method :open_tcp_socket

    def self.open_unix_socket(configuration)
      UNIXSocket.new(configuration.unix_socket)
    end

    private_class_method :open_unix_socket
  end
end

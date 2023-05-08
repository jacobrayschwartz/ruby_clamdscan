# frozen_string_literal: true

require "ruby_clamdscan/socket"
require "ruby_clamdscan/commands/scan"
require "ruby_clamdscan/commands/manage"
require "ruby_clamdscan/commands/status"
require "ruby_clamdscan/configuration"
require "ruby_clamdscan/version"

# Utility for interacting with ClamAV
module RubyClamdscan
  class << self
    # Configuration to use interacting with the ClamAV server
    def configuration
      @configuration ||= Configuration.new

      @configuration
    end

    # Configure RubyClamdscan
    def configure
      yield(configuration)
    end

    # Scans a file
    # @param filepath [String] Path to file in local storage
    # @return [RubyClamdscan::Models::ScanResult] Result from the scan attempt
    # @return [RubyClamdscan::Models::ScanResult]
    # @raise [RubyClamdscan::Errors::VirusDetectedError] if Configuration is set to raise exception and malware is detected
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    def scan_file_from_path(filepath)
      RubyClamdscan::Commands::Scan.scan_file(filepath, @configuration)
    end

    # Scans the contents of the stream passed in
    # @param stream [IO] stream of file contents
    # @return [RubyClamdscan::Models::ScanResult] Result from the scan attempt
    # @return [RubyClamdscan::Models::ScanResult]
    # @raise [RubyClamdscan::Errors::VirusDetectedError] if Configuration is set to raise exception and malware is detected
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    def scan_contents(stream)
      RubyClamdscan::Commands::Scan.scan(stream, @configuration)
    end

    # Attempts to ping the ClamAV server
    # @return [String] "PONG"
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    # @raise [RubyClamdscan::Exceptions::EmptyResponseError] If server response is empty
    def ping_server
      RubyClamdscan::Commands::Status.ping_server(@configuration)
    end

    # Attempts to retrieve the ClamAV server's version information
    # @return [String] Server information
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    # @raise [RubyClamdscan::Exceptions::EmptyResponseError] If server response is empty
    def server_version
      RubyClamdscan::Commands::Status.server_version(@configuration)
    end

    # Replies with statistics about the scan queue, contents of scan queue, and memory usage
    # Because the format of this response is subject to change, this method will only return the string
    # Uses "nSTATS\n", blocks in the returned response will be separated by the \n character
    # @return [String] Format (currently):
    # "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 10 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000375 \n\n
    # MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 1281.773M pools_total 1281.827M\nEND"
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    # @raise [RubyClamdscan::Errors::EmptyResponseError] If server response is empty
    def server_stats
      RubyClamdscan::Commands::Status.server_stats(@configuration)
    end

    # Force ClamAV to reload the virus databases
    # @return [String] "RELOADING"
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    # @raise [RubyClamdscan::Errors::EmptyResponseError] If server response is empty
    def reload_server_database
      RubyClamdscan::Commands::Manage.reload_server_database(@configuration)
    end

    # Shutdown ClamAV server
    # Note: this will completely close socket communication. Server cannot be restarted through this library
    # @raise [RubyClamdscan::Errors::ClamAVCommunicationError] if communication with ClamAV server fails
    # @return [Boolean] true if shutdown command was sent
    def shutdown_server
      RubyClamdscan::Commands::Manage.shutdown_server(@configuration)
    end
  end
end

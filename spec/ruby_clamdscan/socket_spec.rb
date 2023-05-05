# frozen_string_literal: true

require "ruby_clamdscan/configuration"
require "ruby_clamdscan/socket"
require "socket"

RSpec.describe RubyClamdscan::Socket do
  let(:configuration) { RubyClamdscan::Configuration.new }

  describe ".open_clamav_socket" do
    subject(:open_socket) { described_class.open_clamav_socket(configuration) }

    context "when opening a TCP Socket" do
      before do
        configuration.use_tcp_socket = true
      end

      it "attempts to open a TCP Socket with configured values" do
        expect(TCPSocket).to receive(:open).with(configuration.tcp_host, configuration.tcp_port)
        open_socket
      end
    end

    context "when opening a Unix Socket" do
      before do
        configuration.use_tcp_socket = false
      end

      it "attempts to open a UNIXSocket with configured values" do
        expect(UNIXSocket).to receive(:new).with(configuration.unix_socket)
        open_socket
      end
    end
  end
end

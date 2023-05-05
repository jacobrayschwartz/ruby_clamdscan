# frozen_string_literal: true

require "ruby_clamdscan/configuration"
require "ruby_clamdscan/socket"
require "socket"

RSpec.describe RubyClamdscan::Socket do
  let(:configuration) { RubyClamdscan::Configuration.new }

  describe ".open_clamav_socket" do
    subject { RubyClamdscan::Socket.open_clamav_socket(configuration) }

    context "When opening a TCP Socket" do
      before do
        configuration.use_tcp_socket = true
      end

      it "Attempts to open a TCP Socket with configured values" do
        expect(TCPSocket).to receive(:open).with(configuration.tcp_host, configuration.tcp_port)
        subject
      end
    end

    context "When opening a Unix Socket" do
      before do
        configuration.use_tcp_socket = false
      end

      it "Attempts to open a UNIXSocket with configured values" do
        expect(UNIXSocket).to receive(:new).with(configuration.unix_socket)
        subject
      end
    end
  end
end

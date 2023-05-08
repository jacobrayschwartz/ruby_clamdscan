# frozen_string_literal: true

require "ruby_clamdscan/configuration"
require "ruby_clamdscan/socket"
require "ruby_clamdscan/commands/utils"

RSpec.describe RubyClamdscan::Commands::Utils do
  describe ".send_single_command" do
    subject(:send_command) { described_class.send_single_command(command, configuration) }

    let(:command) { "RELOAD" }
    let(:configuration) { RubyClamdscan::Configuration.new }
    let(:mock_socket) { true }
    let(:mock_send) { true }
    let(:mock_get_response) { true }
    let(:mock_close) { true }
    let(:result_content) { ["Some response", nil] }
    let(:socket) { double }

    # rubocop:disable Metrics/AbcSize
    def setup_socket
      allow(RubyClamdscan::Socket).to receive(:open_clamav_socket).and_return(socket) if mock_socket
      expect(socket).to receive(:write) if mock_send
      expect(socket).to receive(:flush) if mock_send
      allow(socket).to receive(:gets).and_return(*result_content) if mock_get_response
      expect(socket).to receive(:close) if mock_close
    end
    # rubocop:enable Metrics/AbcSize

    context "when using the default config" do
      context "when responding with a non-empty string" do
        it "doesn't raise an error" do
          setup_socket
          expect { send_command }.not_to raise_error
        end

        it "returns successfully" do
          setup_socket
          expect(send_command).to match(result_content.join)
        end

        context "when socket has no response" do
          let(:result_content) { [nil] }

          it "raises an error" do
            setup_socket
            expect { send_command }.to raise_error(RubyClamdscan::Errors::EmptyResponseError)
          end
        end

        context "when there's some socket error" do
          let(:mock_socket) { false }
          let(:mock_send) { false }
          let(:cause) { StandardError.new("blah blah blah") }

          before do
            allow(RubyClamdscan::Socket).to receive(:open_clamav_socket).and_raise(cause)
          end

          it "raises an error wrapping the original error" do
            expect { send_command }.to raise_error(RubyClamdscan::Errors::ClamAVCommunicationError)
          end
        end
      end
    end
  end
end

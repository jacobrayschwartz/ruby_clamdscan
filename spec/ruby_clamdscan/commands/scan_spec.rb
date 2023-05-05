# frozen_string_literal: true

# rubocop:disable RSpec/ExpectInHook

require "ruby_clamdscan/configuration"
require "ruby_clamdscan/socket"
require "ruby_clamdscan/commands/scan"

RSpec.describe RubyClamdscan::Commands::Scan do
  describe ".scan" do
    subject(:scan_result) { described_class.scan(nil, configuration) }

    let(:result_content) { "" }
    let(:configuration) { RubyClamdscan::Configuration.new }
    let(:mock_socket) { true }
    let(:mock_send) { true }
    let(:mock_get_response) { true }
    let(:mock_close) { true }

    before do
      socket = double
      allow(RubyClamdscan::Socket).to receive(:open_clamav_socket).and_return(socket) if mock_socket
      expect(described_class).to receive(:send_contents) if mock_send
      allow(described_class).to receive(:get_response).and_return(result_content) if mock_get_response
      expect(socket).to receive(:close) if mock_close
    end

    context "when ClamAV responds with OK" do
      let(:result_content) { "stream: OK\u0000" }

      it "returns a successful result" do
        expect(scan_result.is_successful).to be_truthy
      end
    end

    context "when ClamAV responds with a virus" do
      let(:virus_name) { "rspec.virus" }
      let(:result_content) { "stream: #{virus_name} FOUND\u0000" }

      it "returns a successful result" do
        expect(scan_result.is_successful).to be_truthy
      end

      it "returns true for contains_virus" do
        expect(scan_result.contains_virus).to be_truthy
      end

      it "returns the virus info" do
        expect(scan_result.virus_info).to eq(virus_name)
      end
    end

    context "when ClamAV responds with anything else" do
      let(:result_content) { "blah blah blah\u0000" }

      it "returns an unsuccssful result" do
        expect(scan_result.is_successful).to be_falsey
      end

      it "returns nil for contains_virus" do
        expect(scan_result.contains_virus).to be_nil
      end

      it "returns nil for virus result" do
        expect(scan_result.virus_info).to be_nil
      end

      it "returns the error message" do
        expect(scan_result.error_message).to match(/blah blah blah/)
      end
    end

    context "when some exception gets thrown during the scan process" do
      let(:message) { "some error message" }
      let(:exception) { StandardError.new(message) }

      shared_examples "returns an error response" do
        it "returns the appropriate exception" do
          expect(scan_result.exception).to be_an_instance_of(exception.class)
        end

        it "returns the appropriate error message" do
          expect(scan_result.error_message).to eq(message)
        end
      end

      context "when scan raises error" do
        let(:mock_socket) { false }
        let(:mock_send) { false }
        let(:mock_get_response) { false }
        let(:mock_close) { false }

        before do
          allow(RubyClamdscan::Socket).to receive(:open_clamav_socket).and_raise(exception)
        end

        it_behaves_like "returns an error response"
      end

      context "when send raises error" do
        let(:mock_send) { false }
        let(:mock_get_response) { false }

        before do
          allow(described_class).to receive(:send_contents).and_raise(exception)
        end

        it_behaves_like "returns an error response"
      end

      context "when get_response raises error" do
        let(:mock_get_response) { false }

        before do
          allow(described_class).to receive(:get_response).and_raise(exception)
        end

        it_behaves_like "returns an error response"
      end
    end
  end
end

# rubocop:enable RSpec/ExpectInHook

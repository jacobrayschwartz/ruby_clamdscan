# frozen_string_literal: true

require "ruby_clamdscan/configuration"
require "ruby_clamdscan/socket"
require "ruby_clamdscan/scan"
RSpec.describe RubyClamdscan::Scan do
  describe ".scan" do
    let(:result_content) { "" }
    let(:configuration) { RubyClamdscan::Configuration.new }
    let(:mock_socket) { true }
    let(:mock_send) { true }
    let(:mock_get_response) { true }
    let(:mock_close) { true }

    before(:each) do
      socket = double
      expect(RubyClamdscan::Socket).to receive(:open_clamav_socket).and_return(socket) if mock_socket
      expect(RubyClamdscan::Scan).to receive(:send_contents) if mock_send
      expect(RubyClamdscan::Scan).to receive(:get_response).and_return(result_content) if mock_get_response
      expect(socket).to receive(:close) if mock_close
    end

    subject { RubyClamdscan::Scan.scan(nil, configuration) }

    context "ClamAV responds with OK" do
      let(:result_content) { "stream: OK\u0000" }

      it "returns a successful result" do
        expect(subject.is_successful).to be_truthy
      end
    end

    context "ClamAV responds with a virus" do
      let(:virus_name) { "rspec.virus" }
      let(:result_content) { "stream: #{virus_name} FOUND\u0000" }

      it "returns a virus found result" do
        expect(subject.is_successful).to be_truthy
        expect(subject.contains_virus).to be_truthy
        expect(subject.virus_info).to eq(virus_name)
      end
    end

    context "ClamAV responds with anything else" do
      let(:result_content) { "blah blah blah\u0000" }

      it "returns a virus found result" do
        expect(subject.is_successful).to be_falsey
        expect(subject.contains_virus).to be_nil
        expect(subject.virus_info).to be_nil
        expect(subject.error_message).to match(/blah blah blah/)
      end
    end

    context "Some exception gets thrown during the scan process" do
      let(:message) { "some error message" }
      let(:exception) { StandardError.new(message) }

      shared_examples "returns an error response" do
        it "returns the appropriate error response" do
          expect(subject.exception).to be_an_instance_of(exception.class)
          expect(subject.error_message).to eq(message)
        end
      end

      context "scan raises error" do
        let(:mock_socket) { false }
        let(:mock_send) { false }
        let(:mock_get_response) { false }
        let(:mock_close) { false }

        before(:each) do
          expect(RubyClamdscan::Socket).to receive(:open_clamav_socket).and_raise(exception)
        end

        it_behaves_like "returns an error response"
      end

      context "send raises error" do
        let(:mock_send) { false }
        let(:mock_get_response) { false }

        before(:each) do
          expect(RubyClamdscan::Scan).to receive(:send_contents).and_raise(exception)
        end

        it_behaves_like "returns an error response"
      end

      context "get_response raises error" do
        let(:mock_get_response) { false }

        before(:each) do
          expect(RubyClamdscan::Scan).to receive(:get_response).and_raise(exception)
        end

        it_behaves_like "returns an error response"
      end
    end
  end
end

require 'logstash/devutils/rspec/spec_helper'
require 'logstash/inputs/remote_proc'
require 'net/ssh'
require 'net/ssh/gateway'

describe LogStash::Inputs::RemoteProc do
  let(:config) do
    { 'servers' => [{ 'host' => 'localhost',
                      'port' => 22,
                      'username' => ENV['USER'] }],
      'interval' => 100 }
  end

  let(:queue) { [] }

  before do
    ssh_session = spy('Net::SSH')
    allow(Net::SSH).to receive(:start).with(any_args).and_return(ssh_session)
  end

  it_behaves_like 'an interruptible input plugin' do
  end

  subject { described_class.new(config) }

  context 'when host is reacheable' do
    it '.register' do
      expect { subject.register }.to_not raise_error
    end
  end

  context 'when host is unreacheable' do
    it '.register' do
      rp = described_class.new(
        'servers' => { 'host' => 'not_konown_host' }
      )
      expect { rp.register }.to_not raise_error
    end
  end

  context 'when gateway is provided' do
    it '.register' do
      ssh_gateway = spy('Net::SSH::Gateway')
      expect(Net::SSH::Gateway).to receive(:new).with(any_args)
                                                .and_return(ssh_gateway)
      rp_gateway = described_class.new(
        'servers' => [{ 'host' => 'localhost',
                        'port' => 22,
                        'username' => ENV['USER'],
                        'gateway_host' => '10.0.0.1',
                        'gateway_port' => 22 }],
        'interval' => 100
      )
      expect { rp_gateway.register }.to_not raise_error
    end
  end
end

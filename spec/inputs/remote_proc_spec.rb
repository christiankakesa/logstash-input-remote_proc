# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/inputs/remote_proc'
require 'net/ssh/multi'

describe LogStash::Inputs::RemoteProc do
  let(:config) do
    { 'servers' => [{ 'host' => 'localhost',
                      'port' => 22,
                      'username' => ENV['USER'] }],
      'interval' => 100 }
  end

  let(:queue) { [] }

  before do
    ssh_session = double('ssh_session').as_null_object
    allow(Net::SSH::Multi).to receive(:start).with(on_error: :warn)
      .and_return(ssh_session)
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
end

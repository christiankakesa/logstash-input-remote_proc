# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/inputs/remote_proc'

describe LogStash::Inputs::RemoteProc do
  let(:config) do
    { 'servers' => [{ 'host' => 'localhost',
                      'port' => 22,
                      'username' => 'christian' }],
      'interval' => 100 }
  end

  subject { LogStash::Inputs::RemoteProc.new(config) }

  # it_behaves_like 'an interruptible input plugin' do
  # end

  context 'when host is reacheable' do
    it '.register' do
      expect { subject.register }.to_not raise_error
    end
  end
  context 'when host is unreacheable' do
    it '.register' do
      rp = LogStash::Inputs::RemoteProc.new('servers' => { 'host' => 'not_konown_host' })
      expect { rp.register }.to_not raise_error
    end
  end
end

# encoding: utf-8
require 'logstash/inputs/base'
require 'logstash/namespace'
require 'net/ssh/multi'
require 'socket' # for Socket.gethostname
require 'stud/interval'

module LogStash
  module Inputs
    # Collecting PROCFS metrics through SSH.
    #
    # Supported endpoints :
    #  * /proc/cpuinfo
    #  * /proc/meminfo
    #  * /proc/loadavg
    #  * /proc/vmstat
    #
    # The fallowing example shows how to retrieve system metrics from
    # remote server and output the result to the standard output:
    #
    # [source,ruby]
    # -------------------------------------------------------------------------
    # input {
    #   remote_proc {
    #     servers => [{ host => "remote.server.com" username => "medium" }]
    #   }
    # }
    #
    # output {
    #   stdout { codec => rubydebug }
    # }
    # -------------------------------------------------------------------------
    #
    class RemoteProc < LogStash::Inputs::Base
      # Describe valid keys and default values in `@servers` parameter.
      SERVER_OPTIONS = {
        'host' => 'localhost',     # :string
        'port' => 22,              # :number
        'ssh_private_key' => nil,  # :path (needed if no 'password')
        'username' => ENV['USER'], # :string (default to unix $USER)
        'password' => nil          # :string (needed if no 'ssh_private_key')
      }.freeze

      # Liste of commands for each `/proc` endpoints.
      COMMANDS = {
        cpuinfo: 'cat /proc/cpuinfo',
        meminfo: 'cat /proc/meminfo',
        loadavg: 'cat /proc/loadavg',
        vmstat: 'cat /proc/vmstat'
      }.freeze

      config_name 'remote_proc'

      # If undefined, Logstash will complain, even if codec is unused.
      default :codec, 'plain'

      # Set the list of remote servers
      #
      # The default values are specified in `#{SERVER_OPTIONS}` hash.
      config :servers, validate: :hash, list: true, required: true

      # Set how frequently messages should be sent.
      #
      # The default, `60`, means send a message every second.
      config :interval, validate: :number, default: 60

      def initialize(*args)
        super(*args)
        @ssh_session = Net::SSH::Multi.start(on_error: :warn)
      end

      def register
        # Prepare all server connections
        @servers.each do |s|
          prepare_servers!(s)
          option = if s['ssh_private_key']
                     { auth_methods: ['publickey'], keys: [s['ssh_private_key']] }
                   else
                     { password: s['password'] }
                   end
          @ssh_session.use("#{s['username']}@#{s['host']}:#{s['port']}", option)
        end

        @host = Socket.gethostname
      end # def register

      def run(queue)
        # we can abort the loop if stop? becomes true
        until stop?
          [:proc_cpuinfo, :proc_meminfo, :proc_loadavg, :proc_vmstat]
            .each do |method|
            send(method, queue)
          end

          @ssh_session.loop

          Stud.stoppable_sleep(@interval) { stop? }
        end # loop
      end # def run

      def stop
        @ssh_session.close
      end

      private

      # Return only valide property keys.
      def prepare_servers!(data)
        data.select! { |k| SERVER_OPTIONS.include?(k) }
        data.merge!(SERVER_OPTIONS) { |_key_, old, _new_| old }
      end

      # Process CPUINFO data
      def proc_cpuinfo(queue)
        @ssh_session.exec(COMMANDS[:cpuinfo]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          cpuinfo = {}
          num_cpu = 0
          data.split(/$/).each do |line|
            next if line.tr("\n", '').empty?
            m = /([^\n\t:]+)\s*:\s+(.+)$/.match(line)
            next unless m
            # Apply filters
            value = m[2] # needed to permit assignation and computation
            num_cpu += 1 if m[1].eql?('processor')
            value = m[2].split(/\s+/) if m[1] == 'flags'
            value = m[2].to_i if ['processor',
                                  'physical id',
                                  'siblings',
                                  'core id',
                                  'cpu cores',
                                  'apicid',
                                  'initial apicid',
                                  'cpuid level',
                                  'clflush size',
                                  'cache size',
                                  'cache_alignment'].include?(m[1])
            value = m[2].to_f if ['bogomips',
                                  'cpu MHz'].include?(m[1])
            value = m[2].to_i * 1000 if m[2] =~ /\skb$/i
            index = num_cpu - 1
            cpuinfo[index] = {} unless cpuinfo.include?(index)
            cpuinfo[index][m[1]] = value
          end
          # Other computed fields
          cpuinfo[0]['cpu cores'] = 1 unless cpuinfo[0].include?('cpu cores')
          cpuinfo['threads per core'] = num_cpu / cpuinfo[0]['cpu cores']
          event = LogStash::Event.new(cpuinfo: cpuinfo,
                                      host: @host,
                                      type: @type || 'system-cpuinfo',
                                      metric_name: 'system-cpuinfo',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:cpuinfo])
          decorate(event)
          queue << event
        end
      end

      # Process MEMINFO data
      def proc_meminfo(queue)
        @ssh_session.exec(COMMANDS[:meminfo]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          meminfo = {}
          data.split(/$/).each do |line|
            m = /([^\n\t:]+)\s*:\s+(\d+)(\skb)?$/i.match(line)
            next unless m
            meminfo[m[1]] = m[2].to_i
            meminfo[m[1]] *= 1000 if m[3] # m[3] is not nil if `/KB/i` is found
          end
          meminfo['CalcMemUsed'] = meminfo['MemTotal'] - meminfo['MemFree']
          event = LogStash::Event.new(meminfo: meminfo,
                                      host: @host,
                                      type: @type || 'system-meminfo',
                                      metric_name: 'system-meminfo',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:meminfo])
          decorate(event)
          queue << event
        end
      end

      # Process LOADAVG data
      def proc_loadavg(queue)
        @ssh_session.exec(COMMANDS[:loadavg]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          m = %r{([\d\.]+)\s+([\d\.]+)\s+([\d\.])+\s+(\d+)\/(\d+)\s+(\d+)}.match(data)
          if m && m.length >= 6
            loadavg = { '1minute' => m[1].to_f,
                        '5minutes' => m[2].to_f,
                        '15minutes' => m[3].to_f,
                        'running_processes' => m[4].to_i,
                        'total_processes' => m[5].to_i,
                        'last_running_pid' => m[6].to_i }
            event = LogStash::Event.new(loadavg: loadavg,
                                        host: @host,
                                        type: @type || 'system-loadavg',
                                        metric_name: 'system-loadavg',
                                        remote_host: ch[:host],
                                        command: COMMANDS[:loadavg])
            decorate(event)
            queue << event
          end
        end
      end

      # Process VMSTAT data
      def proc_vmstat(queue)
        @ssh_session.exec(COMMANDS[:vmstat]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          vmstat = {}
          data.split(/$/).each do |line|
            m = /([^\s]+)\s+(\d+)/.match(line)
            vmstat[m[1]] = m[2].to_i if m && m.length >= 3
          end
          event = LogStash::Event.new(vmstat: vmstat,
                                      host: @host,
                                      type: @type || 'system-vmstat',
                                      metric_name: 'system-vmstat',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:vmstat])
          decorate(event)
          queue << event
        end
      end
    end # class LogStash::Inputs::RemoteProc
  end # module LogStash::Inputs
end # module LogStash

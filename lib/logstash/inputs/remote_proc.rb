# encoding: utf-8
require 'logstash/inputs/base'
require 'logstash/namespace'
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
    #  * /proc/diskstats
    #  * /proc/net/dev
    #  * /proc/net/wireless
    #  * /proc/net/mounts
    #  * /proc/net/crypto
    #  * /proc/sysvipc/shm
    #
    # The fallowing example shows how to retrieve system metrics from
    # remote server and output the result to the standard output:
    #
    # [source,ruby]
    # -------------------------------------------------------------------------
    # input {
    #   remote_proc {
    #     servers => [
    #       { host => "remote.server.com" username => "medium" },
    #       { host => "h2.net" username => "poc" gateway_host => "h.gw.net" gateway_username => "user" }
    #     ]
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
        'host' => 'localhost', # :string
        'port' => 22, # :number
        'ssh_private_key' => nil, # :path (needed if no 'password')
        'username' => ENV['USER'] || ENV['USERNAME'] || 'nobody', # :string (default to unix $USER)
        'password' => nil, # :string (needed if no 'ssh_private_key')
        'gateway_host' => nil, # :string
        'gateway_port' => 22, # :number
        'gateway_username' => ENV['USER'] || ENV['USERNAME'] || 'nobody', # :string (default to unix $USER)
        'gateway_password' => nil, # :string
        'gateway_ssh_private_key' => nil # :string
      }.freeze

      # Liste of commands for each `/proc` endpoints.
      COMMANDS = {
        cpuinfo: 'cat /proc/cpuinfo',
        meminfo: 'cat /proc/meminfo',
        loadavg: 'cat /proc/loadavg',
        vmstat: 'cat /proc/vmstat',
        diskstats: 'cat /proc/diskstats',
        netdev: 'cat /proc/net/dev',
        netwireless: 'cat /proc/net/wireless',
        mounts: 'cat /proc/mounts',
        crypto: 'cat /proc/crypto',
        sysvipcshm: 'cat /proc/sysvipc/shm'
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

      def register
        @host = Socket.gethostname

        require 'net/ssh/multi'
        @ssh_session = Net::SSH::Multi.start(on_error: :warn)

        # Don't forget to close all gateways manually in `stop` method.
        @ssh_gateways = []

        # Handle server configuration
        configure_servers
      end # def register

      def run(queue)
        # we can abort the loop if stop? becomes true
        until stop?
          COMMANDS.keys.each do |method|
            send("proc_#{method}", queue)
          end

          @ssh_session.loop

          Stud.stoppable_sleep(@interval) { stop? }
        end # loop
      end # def run

      def stop
        @ssh_session.close
        @ssh_gateways.map(&:shutdown!) unless @ssh_gateways.empty?
      end

      private

      # Return only valide property keys.
      def prepare_servers!(data)
        data.select! { |k| SERVER_OPTIONS.include?(k) }
        data.merge!(SERVER_OPTIONS) { |_key_, old, _new_| old }
      end

      # Prepare all server configuration
      def configure_servers
        @servers.each do |s|
          prepare_servers!(s)

          session_options = { timeout: Integer(@interval * 0.8) }
          session_options[:password] = s['password'] if s['password']
          if s['ssh_private_key']
            session_options[:auth_methods] = ['publickey']
            session_options[:keys] = [s['ssh_private_key']]
          end
          if s['gateway_host']
            gw_opts = { timeout: Integer(@interval * 0.8),
                        port: s['gateway_port'] }
            gw_opts[:password] = s['gateway_password'] if s['gateway_password']
            if s['gateway_ssh_private_key']
              gw_opts[:auth_methods] = ['publickey']
              gw_opts[:keys] = s['gateway_ssh_private_key']
            end
            gw = Net::SSH::Gateway.new(s['gateway_host'],
                                       s['gateway_username'],
                                       gw_opts)
            @ssh_gateways << gw
            session_options[:via] = gw
          end

          @ssh_session.use("#{s['username']}@#{s['host']}:#{s['port']}",
                           session_options)
        end
      end

      # Process SYSVIPCSHM data
      def proc_sysvipcshm(queue)
        @ssh_session.exec(COMMANDS[:sysvipcshm]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          lines = data.split(/$/)
          _ = lines.shift # Remove column name line
          sysvipcshm = {}
          lines.each do |l|
            t = l.strip.split(/\s+/)
            next if t.empty? || t.length < 16
            sysvipcshm[t[1]] = {} # shmid
            sysvipcshm[t[1]]['key'] = t[0]
            sysvipcshm[t[1]]['perms'] = t[2]
            sysvipcshm[t[1]]['size'] = t[3]
            sysvipcshm[t[1]]['cpid'] = t[4]
            sysvipcshm[t[1]]['lpid'] = t[5]
            sysvipcshm[t[1]]['nattch'] = t[6]
            sysvipcshm[t[1]]['uid'] = t[7]
            sysvipcshm[t[1]]['gid'] = t[8]
            sysvipcshm[t[1]]['cuid'] = t[9]
            sysvipcshm[t[1]]['cgid'] = t[10]
            sysvipcshm[t[1]]['atime'] = t[11]
            sysvipcshm[t[1]]['dtime'] = t[12]
            sysvipcshm[t[1]]['ctime'] = t[13]
            sysvipcshm[t[1]]['rss'] = t[14]
            sysvipcshm[t[1]]['swap'] = t[15]
          end
          next if sysvipcshm.empty?
          event = LogStash::Event.new(sysvipcshm: sysvipcshm,
                                      host: @host,
                                      type: @type || 'system-sysvipcshm',
                                      metric_name: 'system-sysvipcshm',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:sysvipcshm],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process CRYPTO data
      def proc_crypto(queue)
        @ssh_session.exec(COMMANDS[:crypto]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          crypto = {}
          current_crypto = ''
          data.split(/$/).each do |line|
            l = line.strip
            next if l.empty?
            t = l.split(/\s+:\s+/)
            next if t.empty? || t.length != 2
            if 'name'.eql?(t[0])
              current_crypto = t[1]
              crypto[current_crypto] = {}
              next
            end
            crypto[current_crypto][t[0]] = t[1] unless current_crypto.empty?
          end
          next if crypto.empty?
          event = LogStash::Event.new(crypto: crypto,
                                      host: @host,
                                      type: @type || 'system-crypto',
                                      metric_name: 'system-crypto',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:crypto],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process MOUNTS data
      def proc_mounts(queue)
        @ssh_session.exec(COMMANDS[:mounts]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          mounts = {}
          data.split(/$/).each do |line|
            t = line.strip.split(/\s+/)
            next if t.empty? || t.length < 6
            # mounted device name
            device = {}
            device['mountPoint'] = t[1]
            device['fsType'] = t[2]
            device['fsOptions'] = t[3].split(/,/)
            device['dump'] = t[4]
            device['pass'] = t[5]
            mounts[t[0]] = [] unless mounts.include?(t[0])
            mounts[t[0]] << device
          end
          next if mounts.empty?
          event = LogStash::Event.new(mounts: mounts,
                                      host: @host,
                                      type: @type || 'system-mounts',
                                      metric_name: 'system-mounts',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:mounts],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process NETWIRELESS data.
      def proc_netwireless(queue)
        @ssh_session.exec(COMMANDS[:netwireless]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          lines = data.split(/$/)
          _ = lines.shift # Remove first line
          _ = lines.shift # Remove second line
          netwireless = {}
          lines.each do |l|
            t = l.strip.split(/[:\s]+/)
            next if t.empty? || t.length < 11 # Last column WE22 is often empty
            netwireless[t[0]] = {}
            netwireless[t[0]]['status'] = t[1].to_i
            netwireless[t[0]]['linkQuality'] = t[2].to_i
            netwireless[t[0]]['levelQuality'] = t[3].to_i
            netwireless[t[0]]['noiseQuality'] = t[4].to_i
            netwireless[t[0]]['nwidDiscarded'] = t[5].to_i
            netwireless[t[0]]['cryptDiscarded'] = t[6].to_i
            netwireless[t[0]]['fragDiscarded'] = t[7].to_i
            netwireless[t[0]]['retryDiscarded'] = t[8].to_i
            netwireless[t[0]]['miscDiscarded'] = t[9].to_i
            netwireless[t[0]]['beaconMissed'] = t[10].to_i
            netwireless[t[0]]['we22'] = t[11].to_i
          end
          next if netwireless.empty?
          event = LogStash::Event.new(netwireless: netwireless,
                                      host: @host,
                                      type: @type || 'system-netwireless',
                                      metric_name: 'system-netwireless',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:netwireless],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process NETDEV data.
      def proc_netdev(queue)
        @ssh_session.exec(COMMANDS[:netdev]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          lines = data.split(/$/)
          _ = lines.shift # Remove first line
          _ = lines.shift # Remove second line
          netdev = {}
          lines.each do |l|
            t = l.strip.split(/[:\s]+/)
            next if t.empty? || t.length < 17
            netdev[t[0]] = {}
            netdev[t[0]]['rxbytes'] = t[1].to_i
            netdev[t[0]]['rxpackets'] = t[2].to_i
            netdev[t[0]]['rxerrs'] = t[3].to_i
            netdev[t[0]]['rxdrop'] = t[4].to_i
            netdev[t[0]]['rxfifo'] = t[5].to_i
            netdev[t[0]]['rxframe'] = t[6].to_i
            netdev[t[0]]['rxcompressed'] = t[7].to_i
            netdev[t[0]]['rxmulticast'] = t[8].to_i
            netdev[t[0]]['txbytes'] = t[9].to_i
            netdev[t[0]]['txpackets'] = t[10].to_i
            netdev[t[0]]['txerrs'] = t[11].to_i
            netdev[t[0]]['txdrop'] = t[12].to_i
            netdev[t[0]]['txfifo'] = t[13].to_i
            netdev[t[0]]['txcolls'] = t[14].to_i
            netdev[t[0]]['txcarrier'] = t[15].to_i
            netdev[t[0]]['txcompressed'] = t[16].to_i
          end
          next if netdev.empty?
          event = LogStash::Event.new(netdev: netdev,
                                      host: @host,
                                      type: @type || 'system-netdev',
                                      metric_name: 'system-netdev',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:netdev],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process DISKSTATS data.
      # https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
      # https://www.kernel.org/doc/Documentation/iostats.txt
      def proc_diskstats(queue)
        @ssh_session.exec(COMMANDS[:diskstats]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          diskstats = {}
          data.split(/$/).each do |line|
            t = line.strip.split(/\s+/)
            next if t.empty? || t.length < 14
            diskstats[t[2]] = {} # device name
            diskstats[t[2]]['major number'] = t[0].to_i
            diskstats[t[2]]['minor number'] = t[1].to_i
            diskstats[t[2]]['reads completed'] = t[3].to_i
            diskstats[t[2]]['reads merged'] = t[4].to_i
            diskstats[t[2]]['sectors read'] = t[5].to_i
            diskstats[t[2]]['time spent reading ms'] = t[6].to_i
            diskstats[t[2]]['writes completed'] = t[7].to_i
            diskstats[t[2]]['writes merged'] = t[8].to_i
            diskstats[t[2]]['sectors written'] = t[9].to_i
            diskstats[t[2]]['time spent writing ms'] = t[10].to_i
            diskstats[t[2]]['io in progress'] = t[11].to_i
            diskstats[t[2]]['io time spent ms'] = t[12].to_i
            diskstats[t[2]]['io weighted time spent ms'] = t[13].to_i
          end
          next if diskstats.empty?
          event = LogStash::Event.new(diskstats: diskstats,
                                      host: @host,
                                      type: @type || 'system-diskstats',
                                      metric_name: 'system-diskstats',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:diskstats],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process VMSTAT data.
      def proc_vmstat(queue)
        @ssh_session.exec(COMMANDS[:vmstat]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          vmstat = {}
          data.split(/$/).each do |line|
            m = /([^\s]+)\s+(\d+)/.match(line)
            vmstat[m[1]] = m[2].to_i if m && m.length >= 3
          end
          next if vmstat.empty?
          event = LogStash::Event.new(vmstat: vmstat,
                                      host: @host,
                                      type: @type || 'system-vmstat',
                                      metric_name: 'system-vmstat',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:vmstat],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process LOADAVG data.
      def proc_loadavg(queue)
        @ssh_session.exec(COMMANDS[:loadavg]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          m = %r{([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\/([^\s]+)\s+([^\s$]+)}.match(data)
          next unless m
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
                                        command: COMMANDS[:loadavg],
                                        message: data)
            decorate(event)
            queue << event
          end
        end
      end

      # Process MEMINFO data.
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
          next if meminfo.empty?
          meminfo['CalcMemUsed'] = meminfo['MemTotal'] - meminfo['MemFree']
          event = LogStash::Event.new(meminfo: meminfo,
                                      host: @host,
                                      type: @type || 'system-meminfo',
                                      metric_name: 'system-meminfo',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:meminfo],
                                      message: data)
          decorate(event)
          queue << event
        end
      end

      # Process CPUINFO data.
      def proc_cpuinfo(queue)
        @ssh_session.exec(COMMANDS[:cpuinfo]) do |ch, stream, data|
          next unless stream == :stdout # ignore :stderr
          cpuinfo = {} # TODO(fenicks): change to array
          num_cpu = 0
          data.split(/$/).each do |line|
            next if line.strip.empty?
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
          next if cpuinfo.empty?
          # Other computed fields
          cpuinfo[0]['cpu cores'] = 1 unless cpuinfo[0].include?('cpu cores')
          cpuinfo['threads per core'] = num_cpu / cpuinfo[0]['cpu cores']
          event = LogStash::Event.new(cpuinfo: cpuinfo,
                                      host: @host,
                                      type: @type || 'system-cpuinfo',
                                      metric_name: 'system-cpuinfo',
                                      remote_host: ch[:host],
                                      command: COMMANDS[:cpuinfo],
                                      message: data)
          decorate(event)
          queue << event
        end
      end
    end # class LogStash::Inputs::RemoteProc
  end # module LogStash::Inputs
end # module LogStash

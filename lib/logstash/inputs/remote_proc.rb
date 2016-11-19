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

        require 'net/ssh'
        require 'net/ssh/gateway'
        @ssh_sessions = []

        # Don't forget to close all gateways manually in `stop` method.
        @ssh_gateways = []

        # Handle server configuration
        configure_servers
      end # def register

      def run(queue)
        # we can abort the loop if stop? becomes true
        until stop?
          @ssh_sessions.each do |ssh|
            COMMANDS.each do |method, command|
              result_data = String.new('')
              error_data = String.new('')
              channel = ssh.open_channel do |chan|
                chan.exec(command) do |ch, success|
                  next unless success
                  # "on_data" called when the process writes to stdout
                  ch.on_data { |_c, data| result_data << data }
                  # "on_extended_data", called when the process writes to stderr
                  ch.on_extended_data { |_ch, _type, data| error_data << data }
                  ch.on_close(&:close)
                end
              end
              channel.wait
              unless error_data.empty?
                error_data.chomp!
                error_data = error_data.force_encoding('UTF-8')
                @logger.warn(error_data)
                next
              end
              next if result_data.empty?
              result = send("proc_#{method}",
                            result_data.force_encoding('UTF-8'))
              next if result.empty?
              event = LogStash::Event.new(
                method => result,
                host: @host,
                type: @type || "system-#{method}",
                metric_name: "system-#{method}",
                remote_host: channel.connection.options[:properties]['host'],
                remote_port: channel.connection.options[:properties]['port'],
                command: command,
                message: result_data
              )
              decorate(event)
              queue << event
            end
            ssh.loop
          end # @ssh_sessions block
          Stud.stoppable_sleep(@interval) { stop? }
        end # until loop
      end # def run

      def stop
        @ssh_sessions.map(&:close)
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

          session_options = { properties: s }
          session_options[:port] = s['port'] if s['port']
          session_options[:password] = s['password'] if s['password']
          if s['ssh_private_key']
            session_options[:auth_methods] = ['publickey']
            session_options[:keys] = [s['ssh_private_key']]
          end
          if s['gateway_host']
            gw_opts = { port: s['gateway_port'] }
            gw_opts[:password] = s['gateway_password'] if s['gateway_password']
            if s['gateway_ssh_private_key']
              gw_opts[:auth_methods] = ['publickey']
              gw_opts[:keys] = s['gateway_ssh_private_key']
            end
            gw = Net::SSH::Gateway.new(s['gateway_host'],
                                       s['gateway_username'],
                                       gw_opts)
            @ssh_gateways << gw
            @ssh_sessions << gw.ssh(s['host'],
                                    s['username'],
                                    session_options)
          else
            @ssh_sessions << Net::SSH.start(s['host'],
                                            s['username'],
                                            session_options)
          end
        end
      end

      # Process SYSVIPCSHM data
      def proc_sysvipcshm(data)
        return {} unless data
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
        sysvipcshm
      end

      # Process CRYPTO data
      def proc_crypto(data)
        return {} unless data
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
        crypto
      end

      # Process MOUNTS data
      def proc_mounts(data)
        return {} unless data
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
        mounts
      end

      # Process NETWIRELESS data.
      def proc_netwireless(data)
        return {} unless data
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
        netwireless
      end

      # Process NETDEV data.
      def proc_netdev(data)
        return {} unless data
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
        netdev
      end

      # Process DISKSTATS data.
      # https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
      # https://www.kernel.org/doc/Documentation/iostats.txt
      def proc_diskstats(data)
        return {} unless data
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
        diskstats
      end

      # Process VMSTAT data.
      def proc_vmstat(data)
        return {} unless data
        vmstat = {}
        data.split(/$/).each do |line|
          m = /([^\s]+)\s+(\d+)/.match(line)
          vmstat[m[1]] = m[2].to_i if m && m.length >= 3
        end
        vmstat
      end

      # Process LOADAVG data.
      def proc_loadavg(data)
        return {} unless data
        m = %r{([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\/([^\s]+)\s+([^\s$]+)}.match(data)
        next unless m
        loadavg = {}
        if m && m.length >= 6
          loadavg.merge!('1minute' => m[1].to_f,
                         '5minutes' => m[2].to_f,
                         '15minutes' => m[3].to_f,
                         'running_processes' => m[4].to_i,
                         'total_processes' => m[5].to_i,
                         'last_running_pid' => m[6].to_i)
        end
        loadavg
      end

      # Process MEMINFO data.
      def proc_meminfo(data)
        return {} unless data
        meminfo = {}
        data.split(/$/).each do |line|
          m = /([^\n\t:]+)\s*:\s+(\d+)(\skb)?$/i.match(line)
          next unless m
          meminfo[m[1]] = m[2].to_i
          meminfo[m[1]] *= 1000 if m[3] # m[3] is not nil if `/KB/i` is found
        end
        unless meminfo.empty?
          meminfo['CalcMemUsed'] = meminfo['MemTotal'] - meminfo['MemFree']
        end
        meminfo
      end

      # Process CPUINFO data.
      def proc_cpuinfo(data)
        return {} unless data
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
        cpuinfo
      end
    end # class LogStash::Inputs::RemoteProc
  end # module LogStash::Inputs
end # module LogStash

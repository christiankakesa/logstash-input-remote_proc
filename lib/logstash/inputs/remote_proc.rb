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
    #  * /proc/stat
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
    #     proc_list => ["cpuinfo", "stat", "meminfo", "diskstats"]
    #   }
    # }
    # -------------------------------------------------------------------------
    #
    # Example with `proc_list => ["_all"]` which is default.
    # [source,ruby]
    # -------------------------------------------------------------------------
    # input {
    #   remote_proc {
    #     servers => [
    #       { host => "remote.server.com" username => "medium" },
    #       { host => "h2.net" username => "poc" gateway_host => "h.gw.net" gateway_username => "user" }
    #     ]
    #     proc_list => ["_all"]
    #   }
    # }
    #
    # -------------------------------------------------------------------------
    # Example with specific procfs prefix path and system reader for certain host.
    # By default the system reader is 'cat' and the procfs prefix path is '/proc'.
    # [source,ruby]
    # -------------------------------------------------------------------------
    # input {
    #   remote_proc {
    #     servers => [
    #       { host => "remote.server.com" username => "medium" system_reader => "dd bs=1 2>/dev/null" proc_prefix_path => "if=/proc"},
    #       { host => "h2.net" username => "poc" gateway_host => "h.gw.net" gateway_username => "user" }
    #     ]
    #     proc_list => ["stat", "meminfo"]
    #   }
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
        'gateway_ssh_private_key' => nil, # :string
        'system_reader' => 'cat', # :string
        'proc_prefix_path' => '/proc' # :string
      }.freeze

      # Liste of commands for each `/proc` endpoints.
      COMMANDS = {
        cpuinfo: '%{system_reader} %{proc_prefix_path}/cpuinfo',
        stat: '%{system_reader} %{proc_prefix_path}/stat',
        meminfo: '%{system_reader} %{proc_prefix_path}/meminfo',
        loadavg: '%{system_reader} %{proc_prefix_path}/loadavg',
        vmstat: '%{system_reader} %{proc_prefix_path}/vmstat',
        diskstats: '%{system_reader} %{proc_prefix_path}/diskstats',
        netdev: '%{system_reader} %{proc_prefix_path}/net/dev',
        netwireless: '%{system_reader} %{proc_prefix_path}/net/wireless',
        mounts: '%{system_reader} %{proc_prefix_path}/mounts',
        crypto: '%{system_reader} %{proc_prefix_path}/crypto',
        sysvipcshm: '%{system_reader} %{proc_prefix_path}/sysvipc/shm'
      }.freeze

      # By default call all procfs method
      DEFAULT_PROC_LIST = ['_all'].freeze

      config_name 'remote_proc'

      # If undefined, Logstash will complain, even if codec is unused.
      default :codec, 'plain'

      # Set the list of remote servers
      #
      # The default values are specified in `#{SERVER_OPTIONS}` hash.
      config :servers, validate: :hash, list: true, required: true

      # List of PROFS information to retrieve
      #
      # Valid values are:
      #
      # [source,ruby]
      # ------------------------------------------------------------------------
      # %w(
      #   cpuinfo stat meminfo loadavg vmstat diskstats
      #   netdev netwireless mounts crypto sysvipcshm
      #  )
      # ------------------------------------------------------------------------
      #
      # By default all metrics are retrieved.
      config :proc_list,
             validate: :array,
             default: ['_all']

      # Set how frequently messages should be sent.
      #
      # The default, `60`, means send a message every second.
      config :interval, validate: :number, default: 60

      def register
        @host = Socket.gethostname

        require 'net/ssh'
        require 'net/ssh/gateway'

        @ssh_sessions = []
        @ssh_gateways = []

        configure!
      end # def register

      def run(queue)
        # we can abort the loop if stop? becomes true
        until stop?
          @ssh_sessions.each do |ssh|
            ssh.properties['_commands'].each do |method, command|
              ssh.open_channel do |chan|
                chan.exec(command) do |ch, success|
                  ch[:result_host] = ssh.properties['host']
                  ch[:result_port] = ssh.properties['port']
                  unless success
                    @logger.warn('CHANNEL_EXEC_UNSUCCESS',
                                 command: command,
                                 host: ch[:result_host],
                                 port: ch[:result_port])
                    next
                  end
                  ch[:result_data] = String.new('')
                  ch[:result_error] = String.new('')
                  # "on_data" called when the process writes to stdout
                  ch.on_data { |_c, data| ch[:result_data] << data }
                  ch.on_process do |_c|
                    unless ch[:result_error].empty?
                      ch[:result_error].chomp!
                      ch[:result_error] = ch[:result_error].force_encoding('UTF-8')
                      @logger.warn(ch[:result_error])
                      next
                    end
                    next if ch[:result_data].empty?
                    result = send("proc_#{method}",
                                  ch[:result_data].force_encoding('UTF-8'))
                    next if result.empty?
                    event = LogStash::Event.new(
                      method => result,
                      host: @host,
                      type: @type || "system-#{method}",
                      metric_name: "system-#{method}",
                      remote_host: ch[:result_host],
                      remote_port: ch[:result_port],
                      command: command,
                      message: ch[:result_data]
                    )
                    decorate(event)
                    queue << event
                  end
                  ch.on_open_failed do |c, code, desc|
                    @logger.warn('CHANNEL_OPEN_FAILED',
                                 host: ch[:result_host],
                                 channel: c,
                                 code: code,
                                 description: desc)
                  end
                  # "on_extended_data", called when the process writes to stderr
                  ch.on_extended_data do |_ch, _type, data|
                    ch[:result_error] << data
                  end
                  ch.on_close(&:close)
                end
                chan.wait
              end
            end
          end # @ssh_sessions block
          @ssh_sessions.each(&:loop)
          Stud.stoppable_sleep(@interval) { stop? }
        end # until loop
      end # def run

      def stop
        @ssh_sessions.each(&:close)
        @ssh_gateways.each(&:shutdown!) unless @ssh_gateways.empty?
      end

      private

      # Return only valide property keys.
      def prepare_servers!(server)
        server.select! { |k| SERVER_OPTIONS.include?(k) }
        server.merge!(SERVER_OPTIONS) { |_key, old, _new| old }
        cmds = if (@proc_list - ['_all']).empty?
                 COMMANDS.dup
               else
                 COMMANDS.select { |k, _| @proc_list.include?(k.to_s) }
               end
        # Replace 'system_reader' and 'proc_prefix_path' for each host command
        server['_commands'] = cmds.each do |k, v|
          cmds[k] = v % { system_reader: server['system_reader'],
                          proc_prefix_path: server['proc_prefix_path'] }
        end
        server['_commands'].freeze
      end

      # Prepare all server configuration
      def configure!
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

      # Process STAT data.
      # http://lxr.free-electrons.com/source/Documentation/filesystems/proc.txt#L1294
      def proc_stat(data)
        return {} unless data
        stat = {}
        data.split(/$/).each do |line|
          m = /^(cpu[0-9]*|intr|ctxt|btime|processes|procs_running|procs_blocked|softirq)\s+(.*)/i.match(line)
          next unless m
          if m[1] =~ /^cpu[0-9]*$/i
            m_sub = m[2].split(/\s+/)
            if m_sub && m_sub.length >= 10
              m_sub.map!(&:to_i)
              stat[m[1]] = {
                user: m_sub[0],
                nice: m_sub[1],
                system: m_sub[2],
                idle: m_sub[3],
                iowait: m_sub[4],
                irq: m_sub[5],
                softirq: m_sub[6],
                steal: m_sub[7],
                guest: m_sub[8],
                guest_nice: m_sub[9]
              }
            end
          elsif m[1] =~ /^ctxt|btime|processes|procs_running|procs_blocked$/i
            stat[m[1]] = m[2].to_i
          elsif m[1] =~ /^intr|softirq$/i
            m_sub = m[2].split(/\s+/)
            next if m_sub.empty?
            total = m_sub.shift.to_i
            stat[m[1]] = { total: total }
            stat[m[1]][:subsequents] = m_sub.map!(&:to_i)
          end
        end
        stat
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

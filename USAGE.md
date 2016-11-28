# Logstash-input-remote_proc
This plugin retrieves `/proc/*` metrics remotely via SSH connections.

## How to use

**Default values for `servers`**

```logstash
servers => [
    {
        host => "localhost"     # :string
        port => 22              # :number
        ssh_private_key => ...  # :path (needed if no 'password'), empty by default
        username => ${USER} || ${USERNAME} || 'nobody' # :string (default to unix $USER)
        password => ...                            # :string (needed if no 'ssh_private_key'), empty by default
        gateway_host => ...                        # :string (if set, gateway is used), empty by default
        gateway_port => 22                         # :number
        gateway_username => ${USER} || ${USERNAME} || 'nobody' # :string (default to unix $USER)
        gateway_password => ...                                # :string (needed if gateway_host is set and no 'ssh_private_key' is given), empty by default
        gateway_ssh_private_key => ...                         # :path (needed if no 'gateway_password'), empty by default
        system_reader => "cat"                                 # :string
        proc_prefix_path => "/proc"                            # :string
    }
]
```

When no password is given, the private key path for both `host` and `gateway_host` are : `$HOME/.ssh/id_dsa`, `$HOME/.ssh2/id_dsa`, `$HOME/.ssh/id_rsa`, and `$HOME/.ssh2/id_rsa`.

**Default values for `proc_list`**

```logstash
proc_list => ["cpuinfo", "stat", "meminfo", "loadavg", "vmstat", "diskstats", "netdev", "netwireless", "mounts", "crypto", "sysvipcshm"]
```

If `proc_list` is not declared all of them are processed. An equivalent declaration is `proc_file => ["_all"]`.

### SSH server with default values and authenticate by private key

```javascript
input { remote_proc { servers => [{}] } }
```

### SSH server with default values and authenticate by private key for `cpuinfo` and `meminfo`

```javascript
input { remote_proc { servers => [{}] proc_list => ["cpuinfo", "meminfo"] } }
```

### With SSH server `host`, `port` and `username` and authenticate by private key

```javascript
input {
    remote_proc {
        servers => [
            { host => "domain.com" port => 22 username => "fenicks" }
        ]
    }
}
```

### With SSH server `host`, `port` and `username` and authenticate by a specific private key file

```javascript
input {
    remote_proc {
        servers => [
            {
                host => "domain.com"
                port => 22
                username => "fenicks"
                ssh_private_key => "${HOME}/.ssh/id_rsa_domain.com"
            }
        ]
    }
}
```

### With SSH server `host`, `port` and `username` and authenticate by password
```javascript
input {
    remote_proc {
        servers => [
            {
                host => "domain.com"
                port => 22
                username => "fenicks"
                password => "my_password!"
            }
        ]
    }
}
```
### With SSH Gateway by with private key file and SSH `host` and `password`
```javascript
input {
    remote_proc {
        servers => [
            {
                host => "domain.com"
                port => 22
                username => "fenicks"
                password => "my_password!"
                gateway_host => "gateway.com"
                gateway_username => "username_passemuraille"
                gateway_port => 4242
                gateway_ssh_private_key => "/path/to/private/key"
            }
        ]
    }
}
```

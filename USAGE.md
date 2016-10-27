# logstash-input-remote_proc
This plugin retrieve `/proc/*` information remotely via SSH connection.

## How to use

**Default values**

```ruby
    SERVER_OPTIONS = {
      'host' => 'localhost',     # :string
      'port' => 22,              # :number
      'ssh_private_key' => nil,  # :path (needed if no 'password')
      'username' => ENV['USER'], # :string (default to unix $USER)
      'password' => nil          # :string (needed if no 'ssh_private_key')
    }.freeze
```

When no password is given, the private key path are : `$HOME/.ssh/id_dsa`, `$HOME/.ssh2/id_dsa`, `$HOME/.ssh/id_rsa`, and `$HOME/.ssh2/id_rsa`.

### SSH server with default values and authenticate by private key

```javascript
input { remote_proc { servers => [{}] } } output { stdout { codec => rubydebug } }
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

output {
    stdout { codec => rubydebug }
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

output {
    stdout { codec => rubydebug }
}
```

### With SSH server `host`, `port` and `username` and authenticate by password
```javascript
input {
    remote_proc {
        servers => [
            { host => "domain.com" port => 22 username => "fenicks" password => "my_password!" }
        ]
    }
}

output {
    stdout { codec => rubydebug }
}
```

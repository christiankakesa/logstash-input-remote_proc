# Logstash-input-remote_proc
This plugin retrieves `/proc/*` metrics remotely via SSH connections.

## How to use

**Default values**

```ruby
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
```

When no password is given, the private key path for both `host` and `gateway_host` are : `$HOME/.ssh/id_dsa`, `$HOME/.ssh2/id_dsa`, `$HOME/.ssh/id_rsa`, and `$HOME/.ssh2/id_rsa`.

### SSH server with default values and authenticate by private key

```javascript
    input { remote_proc { servers => [{}] } }
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

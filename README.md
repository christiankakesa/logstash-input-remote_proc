# Logstash::Inputs::RemoteProc

This plugin retrieve `proc/` information remotely via SSH connection.

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
            { host => "domain.com" port => 22 username => "fenicks" ssh_private_key => "${HOME}/.ssh/id_rsa_domain.com" }
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

# Logstash Plugin

[![Travis Build Status](https://travis-ci.org/fenicks/logstash-input-remote_proc.svg)](https://travis-ci.org/fenicks/logstash-input-remote_proc)

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-awesome", :path => "/your/local/logstash-filter-awesome"
```
- Install plugin
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {awesome {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-awesome.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
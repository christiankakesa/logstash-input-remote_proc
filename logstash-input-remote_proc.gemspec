Gem::Specification.new do |s|
  s.name = 'logstash-input-remote_proc'
  s.version = '0.0.4'
  s.licenses = ['Apache License (2.0)']
  s.summary = 'This Logstash plugin retrieve "PROCFS" system metrics from UNIX like server via SSH.'
  s.description = 'This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program'
  s.authors = ['Christian Kakesa']
  s.email = 'christian@kakesa.net'
  s.homepage = 'https://github.com/fenicks/logstash-input-remote_proc'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*',
                'spec/**/*',
                'vendor/**/*',
                '*.gemspec',
                '*.md',
                'CONTRIBUTORS',
                'Gemfile',
                'LICENSE',
                'NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { 'logstash_plugin' => 'true', 'logstash_group' => 'input' }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '>= 2.0.0'
  s.add_runtime_dependency 'logstash-codec-plain', '>= 3.0.2'
  s.add_runtime_dependency 'net-ssh', '~> 2.9', '>= 2.9.2'
  s.add_runtime_dependency 'net-ssh-multi', '~>1.2', '>= 1.2.1'
  s.add_runtime_dependency 'stud', '~> 0.0', '>= 0.0.22'
  s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
end

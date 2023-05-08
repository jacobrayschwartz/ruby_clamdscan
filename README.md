# RubyClamdscan

Implementing most `clamdscan` commands as a Ruby Gem using socket communication. 

This is a personal project to learn more about how Ruby gem development works and may not be actively developed.

## Installation

Install the gem and add to the application's Gemfile by executing:

    $ bundle add ruby_clamdscan

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install ruby_clamdscan

## Usage

Set the configuration for this gem by using:

```ruby
RubyClamdscan.configure do |conf|
  conf.use_tcp_socket = true
end
```

Scan files by using:
```ruby
RubyClamdscan.scan_file_from_path("/path/to/local/file")
```

or

```ruby
RubyClamdscan.scan_contents(IO)
```

Both return instances of `RubyClamdscan::Models::ScanResults` with information about the scan

### Configuration options
```ruby
RubyClamdscan.configure do |conf|
  conf.use_tcp_socket = true # If using TCP socket, defaults to false to use local unix socket
  conf.tcp_port = 3310 # TCP Port where ClamAV is listening
  conf.tcp_host = "localhost" # Host where ClamAV is listening
  conf.unix_socket = "/tmp/clamd.socket" # If using UNIX socket, what file represents the socket
  conf.chunk_size = 1024 # Size of chunk in bytes to send to ClamAV for scanning
  conf.raise_error_on_empty_response = true # If the socket responds empty, raise `RubyClamdscan::Errors::EmptyResponseError` instead of returning an empty string
  conf.raise_error_on_virus_detected = true # If a virus is detected, raise `RubyClamdscan::Errors::VirusDetectedError` instead of just returning the result
end
```

### Commands
* `RubyClamdscan.ping_server` - Ping server, should respond with "PONG"
* `RubyClamdscan.server_version` - Query ClamAV for server version info - response format may change
* `RubyClamdscan.server_stats` - Query ClamAV for server stats, resources, etc - response format may change
* `RubyClamdscan.reload_server_database` - Tell ClamAV server to reload virus db
* `RubyClamdscan.shutdown_server` - Tell ClamAV server shutdown and stop listening to requests

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jacobrayschwartz/ruby_clamdscan. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/jacobrayschwartz/ruby_clamdscan/blob/main/CODE_OF_CONDUCT.md).

## Code of Conduct

Everyone interacting in the RubyClamdscan project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/jacobrayschwartz/ruby_clamdscan/blob/main/CODE_OF_CONDUCT.md).

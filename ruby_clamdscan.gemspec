# frozen_string_literal: true

require_relative "lib/ruby_clamdscan/version"

Gem::Specification.new do |spec|
  spec.name = "ruby_clamdscan"
  spec.version = RubyClamdscan::VERSION
  spec.authors = ["Jacob Schwartz"]
  spec.email = ["jacob.ray.schwartz@gmail.com"]
  spec.homepage = "https://jacobrayschwartz.com"

  spec.summary = "Wrapper around TCP socket communication with a clamd instance"
  spec.description = "Implements most commands for clamdscan using socket communcation so that you don't need " \
                      "ClamAV or clamdscan installed on the same host as your service"
  # spec.homepage = "TODO: Put your gem's website or public repo URL here."
  spec.license = "GPL-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/jacobrayschwartz/ruby_clamdscan"
  spec.metadata["changelog_uri"] = "https://github.com/jacobrayschwartz/ruby_clamdscan/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end

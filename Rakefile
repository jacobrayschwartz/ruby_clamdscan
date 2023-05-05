# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:spec) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["spec/**/*_spec.rb"]
end

require "rubocop/rake_task"
require "rspec/core/rake_task"

RuboCop::RakeTask.new
RSpec::Core::RakeTask.new(:spec)

task default: %i[spec rubocop]

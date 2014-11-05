#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'redis'

redis=Redis.new
keys=redis.keys "countries:*"
keys.each do |key|
  countries=redis.smembers key
  puts "SADD #{key} #{countries.join(' ')}"
end

#!/usr/bin/env ruby

# == Synopsis
#   It scans postfix mail.log looking for user logins, for each user it stores
#   from which countries is accessing and warns about suspicious activity
#
# == Usage
#   Run it periodically, for example after every log rotation
#
# == Author
#   Lluís Gili
#
# == Copyright
#   Copyright (c) 2007 David Escala. Licensed under the MIT License:
#   http://www.opensource.org/licenses/mit-license.php

require 'rubygems'
require 'bundler/setup'

require 'maxminddb'
require 'syslog'
require 'redis'

class Inspector

  LOGIN_REGEXP=/(imap|pop3)-login: Login: user=<(?<user>\S+)>, .*rip=(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/

  attr_accessor :logins, :ip_country
  attr_reader :redis

  def initialize(log_file)
    @log_file=log_file
    @db=MaxMindDB.new('/var/lib/GeoIP/GeoLite2-Country.mmdb')
    @db.local_ip_alias = ''
    @redis=Redis.new
    @fqdn=`hostname -f`.strip
    @logins={}     # to store logins from new countries
    @ip_country={} # ip lookup cache
  end

  def run
    File.read(mail_log_file).each_line do |l|
      if l =~ LOGIN_REGEXP
        # {"user"=>"user@domain.tld", "ip"=>"1.2.3.4"}
        logged_in = Hash[Regexp.last_match.names.zip(Regexp.last_match.captures)]
        unless ip_country.has_key?(logged_in['ip'])
          self.ip_country[logged_in['ip']] = get_country_code(logged_in['ip'])
        end
        decide(logged_in['ip'],logged_in['user'],ip_country[logged_in['ip']])
      end
    end
    tell_postmaster('Users logged in from new countries', report) if logins.any?
  end

  def decide(ip,user,country)
    unless user.to_s.empty? or country.to_s.empty?
      log "client_address=#{ip} sasl_username=#{user} country=#{country}"
      key="logged_from:#{user}"
      unless redis.sismember(key, country)
        # add to @logins for report purposes
        self.logins[user] ||= {}
        self.logins[user][:sent] ||= redis.smembers("countries:#{user}")
        self.logins[user][:old] ||= redis.smembers(key)
        self.logins[user][:new] ||= []
        self.logins[user][:new] << country unless logins[user][:new].include?(country)
        # store to known countries
        redis.sadd(key, country)
      end
    end
  end

  def report
    str = []
    str << "#{logins.size} users logged in from new countries on host #{@fqdn}:"
    logins.each do |user,data|
      str << "#{user} new login from: #{data[:new].join(', ')} (previous logins: #{data[:old].join(', ')}, sent from: #{data[:sent].join(', ')})"
      str << "inspect with:   redis-cli SMEMBERS logged_from:#{user}"
      str << "remove country: redis-cli SREM <COUNTRY> logged_from:#{user}"
    end
    str.join("\n\n")
  end

  def tell_postmaster(subject,msg)
    postmaster="postmaster@#{@fqdn}"
    cmd="swaks -h-From '#{postmaster}' -t '#{postmaster}' --h-Subject '#{subject}' --body '#{msg}'"
    if __FILE__==$0
      `#{cmd}`
    else
      # puts cmd
    end
    cmd
  end

  def get_country_code(ip)
    begin
      ret=@db.lookup(ip)
      ret.country.iso_code
    rescue IPAddr::InvalidAddressError
      '--'
    end
  end

  def mail_log_file
    if __FILE__==$0
      @log_file
    else
      "spec/mail_log_example.log"
    end
  end

  def log(str)
    #if __FILE__==$0
    #  Syslog.log(Syslog::LOG_INFO, str) if Syslog.opened?
    #else
    #  # puts str
    #end
  end

end

if __FILE__==$0
  log_file = ARGV[0].to_s
  log_file = "/var/log/mail.log.1" unless log_file.size > 0
  app = Inspector.new(log_file)
  app.run
end

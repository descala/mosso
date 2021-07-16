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

  # do not warn countries
  WHITELIST=%w( ES )

  # dovecot logins imap/pop
  LOGIN_REGEXP=/(imap|pop3)-login: Login: user=<(?<user>\S+)>, .*rip=(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
  # roundcube logins, must set $config['log_logins'] = true;
  LOGIN_REGEXP_RC=/Successful login for (?<user>\S+) .* from (?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) in session/

  attr_accessor :logins, :ip_country
  attr_reader :redis

  def initialize(dovecot_log_file, roundcube_log_file)
    @dovecot_log_file=dovecot_log_file
    @roundcube_log_file=roundcube_log_file
    @db=MaxMindDB.new('/var/lib/GeoIP/GeoLite2-Country.mmdb')
    @db.local_ip_alias = ''
    @redis=Redis.new
    @fqdn=`hostname -f`.strip
    @logins={}     # to store logins from new countries
    @ip_country={} # ip lookup cache
    @errors = []
  end

  def run
    # check dovecot logins
    scan_log_file(@dovecot_log_file, LOGIN_REGEXP)
    # check roundcube logins
    scan_log_file(@roundcube_log_file, LOGIN_REGEXP_RC)
  rescue
    @errors << $!.message
  ensure
    if logins.any? or @errors.any?
      # send report
      tell_postmaster("Users logged in from new countries on #{@fqdn}", report)
    end
  end

  def scan_log_file(file, regex)
    to_utf(File.read(file)).each_line do |l|
      if l =~ regex
        # {"user"=>"user@domain.tld", "ip"=>"1.2.3.4"}
        logged_in = Hash[Regexp.last_match.names.zip(Regexp.last_match.captures)]
        unless ip_country.has_key?(logged_in['ip'])
          self.ip_country[logged_in['ip']] = get_country_code(logged_in['ip'])
        end
        decide(logged_in['ip'],logged_in['user'],ip_country[logged_in['ip']])
      end
    end
  end

  def decide(ip,user,country)
    unless user.to_s.empty? or country.to_s.empty? or WHITELIST.include?(country)
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
    @errors.each do |error|
      str << "ERROR: #{error}\n\n"
    end
    str << "#{logins.size} users logged in from new countries on host #{@fqdn}:\n"
    logins.each do |user,data|
      str << "#{user} new login from: #{data[:new].join(', ')} (previous logins: #{data[:old].join(', ')}, sent from: #{data[:sent].join(', ')})"
    end
    str.join("\n")
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
      ''
    end
  end

  def log(str)
    #if __FILE__==$0
    #  Syslog.log(Syslog::LOG_INFO, str) if Syslog.opened?
    #else
    #  # puts str
    #end
  end

  def to_utf(string, from='ISO-8859-1')
    return nil if string.nil?
    unless string.valid_encoding?
      begin
        string.encode!('UTF-8', from)
      rescue Encoding::UndefinedConversionError
        %w(binary ISO-8859-1).each do |encoding|
          next if encoding == from
          break if string.valid_encoding?
          begin
            string.encode!('UTF-8', encoding)
          rescue Encoding::UndefinedConversionError
            string.encode!(
              'UTF-8', from, invalid: :replace, undef: :replace, replace: ''
            )
          end
        end
      end
    end
    # remove BOM
    string.gsub("\xEF\xBB\xBF", '') rescue string
  end

end

if __FILE__==$0
  dovecot_log_file = ARGV[0].to_s
  dovecot_log_file = "/var/log/mail.log.1" unless dovecot_log_file.size > 0
  roundcube_log_file = ARGV[1].to_s
  roundcube_log_file = "/var/log/roundcube/userlogins.log.1" unless roundcube_log_file.size > 0
  app = Inspector.new(dovecot_log_file, roundcube_log_file)
  app.run
end

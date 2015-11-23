#!/usr/bin/env ruby 

# == Synopsis 
#   This is a policy deamon for the Postfix policy delegation protocol
#   It blocks spammers who send SPAM using stolen credentials.
#
# == Usage
#  Append to your master.cf
#
#     mosso  unix  -   n   n   -   0   spawn   user=nobody argv=/path/to/mosso
#
#   in your main.cf
#
#     smtpd_recipient_restrictions = 
#       ...
#       reject_unauth_destination
#       check_policy_service unix:private/mosso
#
# == Author
#   David Escala
#
# == Copyright
#   Copyright (c) 2007 David Escala. Licensed under the MIT License:
#   http://www.opensource.org/licenses/mit-license.php

require 'rubygems'
require 'bundler/setup'

require 'geoip'
require 'syslog'
require 'redis'

require File.expand_path('../whitelist.rb', __FILE__)

class Mosso

  TERMINATOR = "\n\n"

  attr_accessor :attributes, :buffer, :block_time, :whitelist
  attr_reader :redis

  def initialize(stdin=STDIN,stdout=STDOUT)
    @stdin = stdin
    @stdout = stdout
    $stdout.sync = true
    @buffer=[]
    @attributes={}
    @geoip=GeoIP.new('/usr/share/GeoIP/GeoIP.dat',:preload=>true)
    @redis=Redis.new
    @fqdn=`hostname -f`.strip
    @block_time=60
    begin
      @whitelist=WHITELIST
    rescue NameError
      @whitelist=[]
    end
  end

  def run
    while line = @stdin.gets do
      receive_line( line.chomp )
    end
  end

  def receive_line(line)
    unless line.empty?
      buffer << line
    else
      buffer.each do |bline|
        key, value = bline.split( '=' )
        attributes[key.to_sym] = value.strip unless value.nil?
      end
      response(decide(attributes[:client_address],attributes[:sasl_username],get_country_code))
      buffer.clear
      attributes.clear
    end
  end

  def decide(ip,user,country)
    if user.nil? or user.empty?
      "DUNNO"
    else
      log "client_address=#{ip} sasl_username=#{user} country=#{country}"
      key="countries:#{user}"
      if redis.sismember(key, country)
        "DUNNO"
      else
        if whitelist.include?(country)
          redis.sadd(key, country)
          warning = "WARN User #{user} has moved to #{ip} in #{country}, a whitelisted country."
          tell_postmaster warning, "It has been added to its allowed countries.\n\nMosso."
          warning
        else
          block_key="justblock:#{user}"
          if redis.exists(block_key)
            redis.setex block_key, block_time, country
            "REJECT Suspicious activity of #{user} from #{ip} in #{country} has been blocked. Please try again later or contact the administrator."
          else
            redis.setex block_key, block_time, country
            warning = "WARN User #{user} is not allowed to send from #{ip} in #{country}"
            tell_postmaster warning, warning_message_body(user, country, ip)
            warning
          end
        end
      end
    end
  end

  def warning_message_body(user,country,ip=nil)
    %Q(To add this country to the allowed countries of user #{user}
run this command on host #{@fqdn}:

redis-cli SADD countries:#{user} #{country}

and to get its currently allowed countries:

redis-cli SMEMBERS countries:#{user}

#{mail_log_message(ip)}

Mosso.)
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

  def response(action)
    @stdout.puts "action=#{action}#{TERMINATOR}"
  end

  def get_country_code
    begin
      @geoip.country(attributes[:client_address]).country_code2
    rescue SocketError
      '--'
    end
  end

  def mail_log_message(ip)
    relevant_log = grep_mail_log(ip)
    if relevant_log and relevant_log!=''
      "Grep of #{ip} in #{mail_log_file}:\n\n#{relevant_log}"
    end
  end

  def grep_mail_log(ip)
    if ip and ip.to_s!='' and File.exist?(mail_log_file) and File.readable?(mail_log_file)
      `grep '#{ip}' #{mail_log_file}`
    end
  end

  def mail_log_file
    if __FILE__==$0
      "/var/log/mail.log"
    else
      "spec/mail_log_example.log"
    end
  end

  def log(str)
    if __FILE__==$0
      Syslog.log(Syslog::LOG_INFO, str) if Syslog.opened?
    else
      # puts str
    end
  end

end

if __FILE__==$0
  Syslog.open("mosso",Syslog::LOG_PID,Syslog::LOG_MAIL)
  app = Mosso.new(STDIN,STDOUT)
  app.run
end

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

class Mosso

  TERMINATOR = "\n\n"

  attr_accessor :attributes, :buffer

  def initialize(stdin=STDIN,stdout=STDOUT)
    @stdin = stdin
    @stdout = stdout
    $stdout.sync = true
    @buffer=[]
    @attributes={}
    @geoip=GeoIP.new('/usr/share/GeoIP/GeoIP.dat',:preload=>true)
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
      log "client_address=#{attributes[:client_address]} sasl_username=#{attributes[:sasl_username]} country=#{country}"
      response "DUNNO"
      buffer.clear
      attributes.clear
    end
  end

  def response(action)
    @stdout.puts "action=#{action}#{TERMINATOR}"
  end

  def country
    begin
      @geoip.country(attributes[:client_address]).country_code2
    rescue SocketError
      '--'
    end
  end

  def log(str)
    Syslog.log(Syslog::LOG_INFO, str) if Syslog.opened?
  end
end

if __FILE__==$0
  Syslog.open("mosso",Syslog::LOG_PID,Syslog::LOG_MAIL)
  app = Mosso.new(STDIN,STDOUT)
  app.run
end

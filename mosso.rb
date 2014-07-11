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

  def initialize(stdin,stdout)
    Syslog.open("mosso",Syslog::LOG_PID,Syslog::LOG_MAIL)
    @stdin = stdin
    @stdout = stdout
    $stdout.sync = true
    @buffer=[]
    @attributes={}
  end

  def run
    while line = @stdin.gets do
      receive_line( line.chomp )
    end
  end

  def receive_line(line)
    unless line.empty?
      @buffer << line
    else
      @buffer.each do |bline|
        key, value = bline.split( '=' )
        @attributes[key.to_sym] = value.strip unless value.nil?
      end
      Syslog.log(Syslog::LOG_INFO, "client_address=%s", @attributes[:client_address])
      Syslog.log(Syslog::LOG_INFO, "sasl_sender=%s", @attributes[:sasl_sender])
      response "DUNNO"
      @buffer.clear
      @attributes.clear
    end
  end

  def response(action)
    @stdout.puts "action=#{action}#{TERMINATOR}"
  end

end

if __FILE__==$0
  app = Mosso.new(STDIN,STDOUT)
  app.run
end

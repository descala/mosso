mosso
=====

This is a policy deamon for the Postfix policy delegation protocol.

It blocks spammers who send SPAM using stolen credentials.
                                                                             
Usage
-----

Append to your master.cf
                                                                            
   mosso  unix  -   n   n   -   0   spawn   user=nobody argv=/path/to/mosso.rb
                                                                            
 in your main.cf
                                                                            
   smtpd_recipient_restrictions = 
     ...
     reject_unauth_destination
     check_policy_service unix:private/mosso

Requisites
----------

    apt-get install geoip-database-contrib swaks

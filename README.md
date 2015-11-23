mosso
=====

This is a policy deamon for the Postfix policy delegation protocol.

It blocks spammers who send SPAM using stolen credentials.
                                                                             
Install
-------

Run `bundle install` or install `geoip` and `redis` gems.

Append to your master.cf

```
mosso  unix  -   n   n   -   0   spawn   user=nobody argv=/path/to/mosso.rb
```

and in your main.cf

```
smtpd_recipient_restrictions =
  ...
  check_policy_service unix:private/mosso,
  permit_sasl_authenticated
  ...
```

it should be called before `permit_sasl_authenticated`

If you want to include information form `/var/log/mail.log` in notifications,
replace "user=nobody" in master.cf with a user with read access
to `/var/log/mail.log`. Example:

```
adduser mosso --ingroup adm --disabled-login --shell /bin/false
```

Requisites
----------

```
apt-get install geoip-database-contrib swaks redis-server
```

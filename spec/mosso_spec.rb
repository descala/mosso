require_relative '../mosso'
require 'stringio'


RSpec.describe Mosso do
  it "reads Postfix policy delegation protocol" do
    input=<<EOI
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
helo_name=some.domain.tld
queue_id=8045F2AB23
sender=foo@bar.tld
recipient=bar@foo.tld
recipient_count=0
client_address=1.2.3.4
client_name=another.domain.tld
reverse_client_name=another.domain.tld
instance=123.456.7

EOI
    output=StringIO.new
    Mosso.new(StringIO.new(input),output).run
    expect(output.string).to eq("action=DUNNO\n\n")
  end
  it "uses country db" do
    m=Mosso.new
    m.attributes[:client_address]='1.2.3.4'
    expect(m.get_country_code).to eq('US')
    m.attributes[:client_address]='  '
    expect(m.get_country_code).to eq('--')
    m.attributes[:client_address]='176.111.36.1'
    expect(m.get_country_code).to eq('UA')
  end
  it "records first as allowed country & blocks if abused" do
    m=Mosso.new
    m.block_time=1
    m.whitelist=['AU']
    m.redis.del "countries:me@example.tld" # cleanup
    m.redis.del "justblock:me@example.tld"
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to match(/WARN .* whitelisted country/)
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to eq('DUNNO')
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to match(/WARN .* not allowed/)
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to match(/REJECT/)
    sleep 2 # TODO avoid delaying test
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to match(/WARN .* not allowed/)
  end
  it "has a whitelist" do
    m=Mosso.new
    m.whitelist=['UA']
    m.redis.del "countries:me@example.tld" # cleanup
    m.redis.del "justblock:me@example.tld"
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to match(/WARN .* not allowed/)
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to match(/has moved to .* whitelisted country/)
  end
  it "has a default whitelist" do
    m=Mosso.new
    expect(m.whitelist).to include('ES')
  end
  it "issues a warning message with body" do
    m=Mosso.new
    expect(m.warning_message_body('user1','ES')).to match(/redis-cli SADD countries:user1 ES/)
    expect(m.tell_postmaster("Subject","Body")).to match(/--h-Subject 'Subject' --body 'Body'/)
  end
  it "records first as allowed country only for whitelisted countries" do
    m=Mosso.new
    m.block_time=1
    m.whitelist=['UA']
    m.redis.del "countries:me@example.tld" # cleanup
    m.redis.del "justblock:me@example.tld"
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to match(/WARN .* not allowed/)
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to match(/REJECT/)
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to match(/has moved to .* whitelisted country/)
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to eq('DUNNO')
    sleep 2 # TODO avoid delaying test
    expect(m.decide('176.111.36.1','me@example.tld','AU')).to match(/WARN .* not allowed/)
  end
  it "appends relevant mail log" do
    m=Mosso.new
    expect(m.mail_log_file).to eq("spec/mail_log_example.log")
    expect(m.grep_mail_log("1.2.3.4")).to match(/server01/)
    expect(m.grep_mail_log('')).to eq(nil)
    expect(m.grep_mail_log(nil)).to eq(nil)
    expect(m.mail_log_message("1.2.3.4")).to match(/^Grep of 1.2.3.4 in/)
    expect(m.mail_log_message("1.2.3.4")).to match(/server01/)
    expect(m.mail_log_message("5.5.5.5")).to eq(nil)
    expect(m.warning_message_body("user2","US","8.8.8.8")).not_to match(/^Grep of/)
  end
end

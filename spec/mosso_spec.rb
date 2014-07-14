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
  it "uses geoip" do
    m=Mosso.new
    m.attributes[:client_address]='1.2.3.4'
    expect(m.get_country_code).to eq('AU')
    m.attributes[:client_address]='  '
    expect(m.get_country_code).to eq('--')
    m.attributes[:client_address]='176.111.36.1'
    expect(m.get_country_code).to eq('UA')
  end
  it "records first as allowed country" do
    m=Mosso.new
    m.redis.del "countries:me@example.tld" # cleanup
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to eq('DUNNO')
    expect(m.decide('1.2.3.4','me@example.tld','AU')).to eq('DUNNO')
    expect(m.decide('176.111.36.1','me@example.tld','UA')).to match(/not allowed/)
  end
end

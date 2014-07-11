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
end

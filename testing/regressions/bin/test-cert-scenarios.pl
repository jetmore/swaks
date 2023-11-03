#!/usr/bin/env perl


   # 60 --tls-verify-ca   FAIL (bad  ca, bad  host)
   # 61 --tls-verify-ca   FAIL (bad  ca, good host)
   # 62 --tls-verify-ca   PASS (good ca, bad  host)
   # 63 --tls-verify-ca   PASS (good ca, good host)
   # 64 --tls-verify-host FAIL (bad  ca, bad  host)
   # 65 --tls-verify-host PASS (bad  ca, good host)
   # 66 --tls-verify-host FAIL (good ca, bad  host)
   # 67 --tls-verify-host PASS (good ca, good host)
   # 68 --tls-verify      FAIL (bad  ca, bad  host)
   # 69 --tls-verify      FAIL (bad  ca, good host)
   # 70 --tls-verify      FAIL (good ca, bad  host)
   # 71 --tls-verify      PASS (good ca, good host)


# ERIFY=$1      # like "" / --tls-verify / --tls-verify-ca / --tls-verify-host
# CA=$2          # like "" / ../certs/ca.pem / ../certs/ca-other.pem
# TARGET=$3      # like "" / node.example.com / signed.example.com / etc
# SERVER_CERT=$4 # like node.example.com / signed.example.com / etc

my @tests = (
	{
		id => 60,
		verify => '--tls-verify-ca',
		ca => '../certs/ca-other.pem',
		target => 'signed.example.com',
		server_cert => 'node.example.com',
		expect => '# 60 --tls-verify-ca   FAIL (bad  ca, bad  host)',
	},
	{
		id => 61,
		verify => '--tls-verify-ca',
		ca => '../certs/ca-other.pem',
		target => 'signed.example.com',
		server_cert => 'signed.example.com',
		expect => '# 61 --tls-verify-ca   FAIL (bad  ca, good host)',
	},
	{
		id => 62,
		verify => '--tls-verify-ca',
		ca => '../certs/ca.pem',
		target => 'signed.example.com',
		server_cert => 'node.example.com',
		expect => '# 62 --tls-verify-ca   PASS (good ca, bad  host)',
	},
	{
		id => 63,
		verify => '--tls-verify-ca',
		ca => '../certs/ca.pem',
		target => 'signed.example.com',
		server_cert => 'signed.example.com',
		expect => '# 63 --tls-verify-ca   PASS (good ca, good host)',
	},
	{
		id => 64,
		verify => '--tls-verify-host',
		ca => '../certs/ca-other.pem',
		target => 'signed.example.com',
		server_cert => 'node.example.com',
		expect => '# 64 --tls-verify-host FAIL (bad  ca, bad  host)',
	},
	{
		id => 65,
		verify => '--tls-verify-host',
		ca => '../certs/ca-other.pem',
		target => 'signed.example.com',
		server_cert => 'signed.example.com',
		expect => '# 65 --tls-verify-host PASS (bad  ca, good host)',
	},
	{
		id => 66,
		verify => '--tls-verify-host',
		ca => '../certs/ca.pem',
		target => 'signed.example.com',
		server_cert => 'node.example.com',
		expect => '# 66 --tls-verify-host FAIL (good ca, bad  host)',
	},
	{
		id => 67,
		verify => '--tls-verify-host',
		ca => '../certs/ca.pem',
		target => 'signed.example.com',
		server_cert => 'signed.example.com',
		expect => '# 67 --tls-verify-host PASS (good ca, good host)',
	},
	{
		id => 68,
		verify => '--tls-verify',
		ca => '../certs/ca-other.pem',
		target => 'signed.example.com',
		server_cert => 'node.example.com',
		expect => '# 68 --tls-verify      FAIL (bad  ca, bad  host)',
	},
	{
		id => 69,
		verify => '--tls-verify',
		ca => '../certs/ca-other.pem',
		target => 'signed.example.com',
		server_cert => 'signed.example.com',
		expect => '# 69 --tls-verify      FAIL (bad  ca, good host)',
	},
	{
		id => 70,
		verify => '--tls-verify',
		ca => '../certs/ca.pem',
		target => 'signed.example.com',
		server_cert => 'node.example.com',
		expect => '# 70 --tls-verify      FAIL (good ca, bad  host)',
	},
	{
		id => 71,
		verify => '--tls-verify',
		ca => '../certs/ca.pem',
		target => 'signed.example.com',
		server_cert => 'signed.example.com',
		expect => '# 71 --tls-verify      PASS (good ca, good host)',
	},
);

foreach my $test (@tests) {
	print "running: '$test->{verify}' '$test->{ca}' '$test->{target}' '$test->{server_cert}'\n";
	print "expecting: $test->{expect}\n";
	system("./test-cert-scenarios.sh '$test->{verify}' '$test->{ca}' '$test->{target}' '$test->{server_cert}'");
}

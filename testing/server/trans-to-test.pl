#!/usr/bin/env perl

# incredibly simple script to translate real swaks output transcript (used for reference) into a script (or partial script) that can be consumed by
# the test server

# for instance:
my $foo = <<EOCOMMENT;
cat <<'EOM' | ./trans-to-test.pl > part-601-auth-login-success.txt
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> dmFsaWR1c2Vy
<-  334 UGFzc3dvcmQ6
 -> dmFsaWRwYXNzd29yZA==
<-  235 Authentication succeeded
EOM
cat part-601-auth-login-success.txt
#  -> AUTH LOGIN
get_line();
# <-  334 VXNlcm5hbWU6
send_line("334 VXNlcm5hbWU6");
#  -> dmFsaWR1c2Vy
get_line();
# <-  334 UGFzc3dvcmQ6
send_line("334 UGFzc3dvcmQ6");
#  -> dmFsaWRwYXNzd29yZA==
get_line();
# <-  235 Authentication succeeded
send_line("235 Authentication succeeded");
EOCOMMENT

while (my $line = <>) {
	chomp($line);
	my $oLine = $line;

	print "# $oLine\n";
	if ($line =~ s|^<[-~]  ||) {
		print "send_line(\"$line\");\n";
	}
	elsif ($line =~ s|^ [-~]> ||) {
		print "get_line();\n";
	}
	else {
		print "ERROR UNKNOWN LINE\n";
	}
}

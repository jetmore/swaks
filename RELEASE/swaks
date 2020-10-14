#!/usr/bin/perl

# use 'swaks --help' to view documentation for this program
#
#      Homepage: http://jetmore.org/john/code/swaks/
#   Online Docs: http://jetmore.org/john/code/swaks/latest/doc/ref.txt
#                http://jetmore.org/john/code/swaks/faq.html
# Announce List: send mail to updates-swaks@jetmore.net
#   Project RSS: http://jetmore.org/john/blog/c/swaks/feed/
#       Twitter: http://www.twitter.com/SwaksSMTP

use strict;

$|            = 1;
my($p_name)   = $0 =~ m|/?([^/]+)$|;
my $p_version = build_version("20201014.0", '$Id$');
my $p_usage   = "Usage: $p_name [--help|--version] (see --help for details)";
my $p_cp      = <<'EOM';
        Copyright (c) 2003-2008,2010-2020 John Jetmore <jj33@pobox.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
EOM

# Get all input provided to our program, via file, env, command line, etc
my %O = %{ load_args() };

# before we do anything else, check for --help and --version
if (get_arg('help', \%O)) {
	ext_usage();
	exit;
}
if (get_arg('version', \%O)) {
	print "$p_name version $p_version\n\n$p_cp\n";
	exit;
}

# Get our functional dependencies and then print and exit early if requested
load_dependencies();
if (get_arg('get_support', \%O)) {
	test_support();
	exit(0);
}

# This 'synthetic' command line used for debug and reference
$G::cmdline = reconstruct_options(\%O);

# We need to fix things up a bit and set a couple of global options
my $opts = process_args(\%O);

if (scalar(keys(%G::dump_args))) {
	if (my $running_state = get_running_state($opts, \%G::dump_args)) {
		# --dump is intended as a debug tool for swaks internally.  Always,
		# unconditionally, show the user's auth password if one is given
		$running_state =~ s/'%RAW_PASSWORD_STRING%'/shquote($opts->{a_pass})/ge;
		print $G::trans_fh_oh $running_state;
	}
	exit(0);
}
elsif ($G::dump_mail) {
	# if the user just wanted to generate an email body, dump it now and exit
	$opts->{data} =~ s/\n\.\Z//;
	print $G::trans_fh_oh $opts->{data};
	exit(0);
}

# we're going to abstract away the actual connection layer from the mail
# process, so move the act of connecting into its own sub.  The sub will
# set info in global hash %G::link
# XXX instead of passing raw data, have processs_opts create a link_data
# XXX hash that we can pass verbatim here
open_link();

sendmail($opts->{from}, $opts->{to}, $opts->{helo}, $opts->{data},
         $opts->{a_user}, $opts->{a_pass}, $opts->{a_type});

teardown_link();

exit(0);

sub teardown_link {
	if ($G::link{type} eq 'socket-inet' || $G::link{type} eq 'socket-unix') {
		# XXX need anything special for tls teardown?
		close($G::link{sock});
		ptrans(11,  "Connection closed with remote host.");
	} elsif ($G::link{type} eq 'pipe') {
		delete($SIG{PIPE});
		$SIG{CHLD} = 'IGNORE';
		close($G::link{sock}{wr});
		close($G::link{sock}{re});
		ptrans(11,  "Connection closed with child process.");
	}
}

sub open_link {
	if ($G::link{type} eq 'socket-inet') {
		ptrans(11, 'Trying ' . $G::link{server} . ':' . $G::link{port} . '...');
		$@ = "";

		my @extra_options = ();
		push(@extra_options, "LocalAddr", $G::link{lint})  if ($G::link{lint});
		push(@extra_options, "LocalPort", $G::link{lport}) if ($G::link{lport});

		# INET6 also supports v4, so use it for everything if it's available.  That
		# allows the module to handle A vs AAAA records on domain lookups where the
		# user hasn't set a specific ip version to be used.  If INET6 isn't available
		# and it's a domain that only has AAAA records, INET will just handle it like
		# a bogus record and we just won't be able to connect
		if (avail("ipv6")) {
			if ($G::link{force_ipv6}) {
				push(@extra_options, "Domain", Socket::AF_INET6() );
			} elsif ($G::link{force_ipv4}) {
				push(@extra_options, "Domain", Socket::AF_INET() );
			}

			$G::link{sock} = IO::Socket::INET6->new(
				PeerAddr  => $G::link{server},
				PeerPort  => $G::link{port},
				Proto     => 'tcp',
				Timeout   => $G::link{timeout},
				@extra_options
			);
		} else {
			$G::link{sock} = IO::Socket::INET->new(
				PeerAddr  => $G::link{server},
				PeerPort  => $G::link{port},
				Proto     => 'tcp',
				Timeout   => $G::link{timeout},
				@extra_options
			);
		}

		if ($@) {
			ptrans(12, "Error connecting" . ($G::link{lint} ? " $G::link{lint}" : '') .
			           " to $G::link{server}:$G::link{port}:\n\t$@");
			exit(2);
		}
		ptrans(11, "Connected to $G::link{server}.");
	} elsif ($G::link{type} eq 'socket-unix') {
		ptrans(11, 'Trying ' . $G::link{sockfile} . '...');
		$SIG{PIPE} = 'IGNORE';
		$@ = "";
		$G::link{sock} = IO::Socket::UNIX->new(Peer => $G::link{sockfile}, Timeout => $G::link{timeout});

		if ($@) {
			ptrans(12, 'Error connecting to ' . $G::link{sockfile} . ":\n\t$@");
			exit(2);
		}
		ptrans(11, 'Connected to ' . $G::link{sockfile} . '.');
	} elsif ($G::link{type} eq 'pipe') {
		$SIG{PIPE} = 'IGNORE';
		$SIG{CHLD} = 'IGNORE';
		ptrans(11, "Trying pipe to $G::link{process}...");
		eval{ open2($G::link{sock}{re}, $G::link{sock}{wr}, $G::link{process}); };

		if ($@) {
			ptrans(12, 'Error connecting to ' . $G::link{process} . ":\n\t$@");
			exit(2);
		}
		select((select($G::link{sock}{wr}), $| = 1)[0]);
		select((select($G::link{sock}{re}), $| = 1)[0]);
		ptrans(11, 'Connected to ' . $G::link{process} . '.');
	} else {
		ptrans(12, 'Unknown or unimplemented connection type ' . $G::link{type});
		exit(3);
	}
}

sub sendmail {
	my $from    = shift; # envelope-from
	my $to      = shift; # envelope-to
	my $helo    = shift; # who am I?
	my $data    = shift; # body of message (content after DATA command)
	my $a_user  = shift; # what user to auth with?
	my $a_pass  = shift; # what pass to auth with
	my $a_type  = shift; # what kind of auth (this must be set to to attempt)
	my $ehlo    = {};    # If server is esmtp, save advertised features here

	do_smtp_proxy() if ($G::proxy{try});

	# start up tls if -tlsc specified
	if ($G::tls_on_connect) {
		if (start_tls()) {
			tls_post_start();
			do_smtp_drop()     if ($G::drop_after eq 'tls');
			do_smtp_quit(1, 0) if ($G::quit_after eq 'tls');
		} else {
			ptrans(12, "TLS startup failed ($G::link{tls}{res})");
			exit(29);
		}
	}

	# read the server's 220 banner.
	do_smtp_gen(undef, '220') || do_smtp_quit(1, 21);
	do_smtp_drop()     if ($G::drop_after eq 'connect');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'connect');

	# Send a HELO string
	$G::drop_before_read = 1 if ($G::drop_after_send eq 'first-helo');
	do_smtp_helo($helo, $ehlo, $G::protocol) || do_smtp_quit(1, 22);
	do_smtp_drop()     if ($G::drop_after eq 'first-helo');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'first-helo');

	if ($G::xclient{before_tls}) {
		xclient_try($helo, $ehlo);
	}

	# handle TLS here if user has requested it
	if ($G::tls) {
		# 0 = tls succeeded
		# 1 = tls not advertised
		# 2 = tls advertised and attempted negotiations failed
		# note there's some duplicate logic here (with process_args) but I think
		# it's best to do as thorough a job covering the options in both places
		# so as to minimize chance of options falling through the cracks
		$G::drop_before_read = 1 if ($G::drop_after_send eq 'tls');
		my $result = do_smtp_tls($ehlo);
		if ($result == 1) {
			ptrans(12, "Host did not advertise STARTTLS");
			do_smtp_quit(1, 29) if (!$G::tls_optional);
		} elsif ($result == 2) {
			ptrans(12, "STARTTLS attempted but failed");
			exit(29) if ($G::tls_optional != 1);
		}
	} elsif ($G::tls_optional == 2 && $ehlo->{STARTTLS}) {
		ptrans(12, "TLS requested, advertised, and locally unavailable.  Exiting");
		do_smtp_quit(1, 29);
	}
	do_smtp_drop()     if ($G::drop_after eq 'tls');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'tls');

	#if ($G::link{tls}{active} && $ehlo->{STARTTLS}) {
	if ($G::link{tls}{active} && !$G::tls_on_connect) {
		# According to RFC3207, we need to forget state info and re-EHLO here
		$ehlo = {};
		$G::drop_before_read = 1 if ($G::drop_after_send eq 'helo');
		do_smtp_helo($helo, $ehlo, $G::protocol) || do_smtp_quit(1, 32);
	}
	do_smtp_drop()     if ($G::drop_after_send eq 'helo'); # haaaack.  Need to use first-helo for this. Just quit here to prevent the mail from being delivered
	do_smtp_drop()     if ($G::drop_after eq 'helo');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'helo');

	if (!$G::xclient{before_tls}) {
		xclient_try($helo, $ehlo);
	}

	# handle auth here if user has requested it
	if ($a_type) {
		# 0 = auth succeeded
		# 1 = auth not advertised
		# 2 = auth advertised but not attempted, no matching auth types
		# 3 = auth advertised but not attempted, auth not supported
		# 4 = auth advertised and attempted but no type succeeded
		# note there's some duplicate logic here (with process_args) but I think
		# it's best to do as thorough a job covering the options in both places
		# so as to minimize chance of options falling through the cracks
		$G::drop_before_read = 1 if ($G::drop_after_send eq 'auth');
		my $result = do_smtp_auth($ehlo, $a_type, $a_user, $a_pass);
		if ($result == 1) {
			ptrans(12, "Host did not advertise authentication");
			do_smtp_quit(1, 28) if (!$G::auth_optional);
		} elsif ($result == 2) {
			if ($G::auth_type eq 'ANY') {
				ptrans(12, "Auth not attempted, no advertised types available");
				do_smtp_quit(1, 28) if ($G::auth_optional != 1);
			} else {
				ptrans(12, "Auth not attempted, requested type not available");
				do_smtp_quit(1, 28) if (!$G::auth_optional);
			}
		} elsif ($result == 3) {
			ptrans(12, "Auth advertised but not supported locally");
			do_smtp_quit(1, 28) if ($G::auth_optional != 1);
		} elsif ($result == 4) {
			ptrans(12, "No authentication type succeeded");
			do_smtp_quit(1, 28) if ($G::auth_optional != 1);
		}
	} elsif ($G::auth_optional == 2 && $ehlo->{AUTH}) {
		ptrans(12, "Auth requested, advertised, and locally unavailable.  Exiting");
		do_smtp_quit(1, 28);
	}
	do_smtp_drop()     if ($G::drop_after eq 'auth');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'auth');

	# send MAIL
	# 0 = mail succeeded
	# 1 = prdr required but not advertised
	$G::drop_before_read = 1 if ($G::drop_after_send eq 'mail');
	my $result = do_smtp_mail($ehlo, $from); # failures in this handled by smtp_mail_callback
	if ($result == 1) {
		ptrans(12, "Host did not advertise PRDR support");
		do_smtp_quit(1, 30);
	}
	do_smtp_drop()     if ($G::drop_after eq 'mail');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'mail');

	# send RCPT (sub handles multiple, comma-delimited recips)
	$G::drop_before_read = 1 if ($G::drop_after_send eq 'rcpt');
	do_smtp_rcpt($to); # failures in this handled by smtp_rcpt_callback
	                   # note that smtp_rcpt_callback increments
	                   # $G::smtp_rcpt_failures at every failure.  This and
	                   # $G::smtp_rcpt_total are used after DATA for LMTP
	do_smtp_drop()     if ($G::drop_after eq 'rcpt');
	do_smtp_quit(1, 0) if ($G::quit_after eq 'rcpt');

	# send DATA
	$G::drop_before_read = 1 if ($G::drop_after_send eq 'data');
	do_smtp_gen('DATA', '354') || do_smtp_quit(1, 25);
	do_smtp_drop() if ($G::drop_after eq 'data');

	# send the actual data
	$G::drop_before_read = 1 if ($G::drop_after_send eq 'dot');
	do_smtp_data($data, $G::suppress_data) || do_smtp_quit(1, 26);
	do_smtp_drop() if ($G::drop_after eq 'dot');

	# send QUIT
	do_smtp_quit(0) || do_smtp_quit(1, 27);
}

sub xclient_try {
	my $helo = shift;
	my $ehlo = shift;

	if ($G::xclient{try}) {
		# 0 - xclient succeeded normally
		# 1 - xclient not advertised
		# 2 - xclient advertised but not attempted, mismatch in requested attrs
		# 3 - xclient attempted but did not succeed
		$G::drop_before_read = 1 if ($G::drop_after_send eq 'xclient');
		my $result = do_smtp_xclient($ehlo);
		if ($result == 1) {
			ptrans(12, "Host did not advertise XCLIENT");
			do_smtp_quit(1, 33) if (!$G::xclient{optional});
		} elsif ($result == 2) {
			ptrans(12, "Host did not advertise requested XCLIENT attributes");
			do_smtp_quit(1, 33) if (!$G::xclient{optional});
		} elsif ($result == 3) {
			ptrans(12, "XCLIENT attempted but failed.  Exiting");
			do_smtp_quit(1, 33) if ($G::xclient{optional} != 1);
		} else {
			do_smtp_drop()     if ($G::drop_after eq 'xclient');
			do_smtp_quit(1, 0) if ($G::quit_after eq 'xclient');

			# re-helo if the XCLIENT command succeeded
			$G::drop_before_read = 1 if ($G::drop_after_send eq 'helo');
			do_smtp_helo($helo, $ehlo, $G::protocol) || do_smtp_quit(1, 34);
			do_smtp_drop()     if ($G::drop_after eq 'helo');
			do_smtp_quit(1, 0) if ($G::quit_after eq 'helo');
		}
	}
}

sub tls_post_start {
	ptrans(11, "TLS started with cipher $G::link{tls}{cipher_string}");
	if ($G::link{tls}{local_cert_subject}) {
		ptrans(11, "TLS local DN=\"$G::link{tls}{local_cert_subject}\"");
	} else {
		ptrans(11, "TLS no local certificate set");
	}
	ptrans(11, "TLS peer DN=\"$G::link{tls}{cert_subject}\"");

	if ($G::tls_get_peer_cert eq 'STDOUT') {
		ptrans(11, $G::link{tls}{cert_x509});
	} elsif ($G::tls_get_peer_cert) {
		open(CERT, ">$G::tls_get_peer_cert") ||
			ptrans(12, "Couldn't open $G::tls_get_peer_cert for writing: $!");
		print CERT $G::link{tls}{cert_x509}, "\n";
		close(CERT);
	}
}

sub start_tls {
	my %t         = (); # This is a convenience var to access $G::link{tls}{...}
	$G::link{tls} = \%t;

	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
	if (!($t{con} = Net::SSLeay::CTX_new())) {
		$t{res} = "CTX_new(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
		return(0);
	}

	my $ctx_options = &Net::SSLeay::OP_ALL;
	if (scalar(@G::tls_protocols)) {
		if ($G::tls_protocols[0] =~ /^no_/i) {
			foreach my $p (@G::tls_supported_protocols) {
				if (grep /^no_$p$/i, @G::tls_protocols) {
					no strict "refs";
					$ctx_options |= &{"Net::SSLeay::OP_NO_$p"}();
				}
			}
		} else {
			foreach my $p (@G::tls_supported_protocols) {
				if (!grep /^$p$/i, @G::tls_protocols) {
					no strict "refs";
					$ctx_options |= &{"Net::SSLeay::OP_NO_$p"}();
				}
			}
		}
	}
	Net::SSLeay::CTX_set_options($t{con}, $ctx_options);
	Net::SSLeay::CTX_set_verify($t{con}, 0x01, 0) if ($G::tls_verify);

	if ($G::tls_ca_path) {
		my @args = ('', $G::tls_ca_path);
		@args    = ($G::tls_ca_path, '') if (-f $G::tls_ca_path);
		if (!Net::SSLeay::CTX_load_verify_locations($t{con}, @args)) {
			$t{res} = "Unable to set set CA path to (" . join(',', @args) . "): "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	} else {
		Net::SSLeay::CTX_set_default_verify_paths($t{con});
	}

	if ($G::tls_cipher) {
		if (!Net::SSLeay::CTX_set_cipher_list($t{con}, $G::tls_cipher)) {
			$t{res} = "Unable to set cipher list to $G::tls_cipher: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	}
	if ($G::tls_cert && $G::tls_key) {
		if (!Net::SSLeay::CTX_use_certificate_file($t{con}, $G::tls_cert, &Net::SSLeay::FILETYPE_PEM)) {
			$t{res} = "Unable to add cert file $G::tls_cert to SSL CTX: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
		if (!Net::SSLeay::CTX_use_PrivateKey_file($t{con}, $G::tls_key, &Net::SSLeay::FILETYPE_PEM)) {
			$t{res} = "Unable to add key file $G::tls_key to SSL CTX: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	}

	if (!($t{ssl} = Net::SSLeay::new($t{con}))) {
		$t{res} = "new(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
		return(0);
	}

	if ($G::tls_sni_hostname) {
		if (!Net::SSLeay::set_tlsext_host_name($t{ssl}, $G::tls_sni_hostname)) {
			$t{res} = "Unable to set SNI hostname to $G::tls_sni_hostname: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	}

	if ($G::link{type} eq 'pipe') {
		Net::SSLeay::set_wfd($t{ssl}, fileno($G::link{sock}{wr})); # error check?
		Net::SSLeay::set_rfd($t{ssl}, fileno($G::link{sock}{re})); # error check?
	} else {
		Net::SSLeay::set_fd($t{ssl}, fileno($G::link{sock})); # error check?
	}

	$t{active} = Net::SSLeay::connect($t{ssl}) == 1 ? 1 : 0;
	if (!$t{active}) {
		$t{res} = "connect(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
		return(0);
	}

	# egrep 'define.*VERSION\b' *.h
	# when adding new types here, see also the code that pushes supported values onto tls_supported_protocols
	$t{version} = Net::SSLeay::version($t{ssl});
	if ($t{version} == 0x0002) {
		$t{version} = "SSLv2";    # openssl/ssl2.h
	} elsif ($t{version} == 0x0300) {
		$t{version} = "SSLv3";    # openssl/ssl3.h
	} elsif ($t{version} == 0x0301) {
		$t{version} = "TLSv1";    # openssl/tls1.h
	} elsif ($t{version} == 0x0302) {
		$t{version} = "TLSv1.1";  # openssl/tls1.h
	} elsif ($t{version} == 0x0303) {
		$t{version} = "TLSv1.2";  # openssl/tls1.h
	} elsif ($t{version} == 0x0304) {
		$t{version} = "TLSv1.3";  # openssl/tls1.h
	} elsif ($t{version} == 0xFEFF) {
		$t{version} = "DTLSv1";   # openssl/dtls1.h
	} elsif ($t{version} == 0xFEFD) {
		$t{version} = "DTLSv1.2"; # openssl/dtls1.h
	} else {
		$t{version} = sprintf("UNKNOWN(0x%04X)", $t{version});
	}
	$t{cipher}          = Net::SSLeay::get_cipher($t{ssl});
	if (!$t{cipher}) {
		$t{res} = "empty response from get_cipher()";
		return(0);
	}
	$t{cipher_bits}     = Net::SSLeay::get_cipher_bits($t{ssl}, undef);
	if (!$t{cipher_bits}) {
		$t{res} = "empty response from get_cipher_bits()";
		return(0);
	}
	$t{cipher_string}   = sprintf("%s:%s:%s", $t{version}, $t{cipher}, $t{cipher_bits});
	$t{cert}            = Net::SSLeay::get_peer_certificate($t{ssl});
	if (!$t{cert}) {
		$t{res} = "error response from get_peer_certificate()";
		return(0);
	}
	chomp($t{cert_x509} = Net::SSLeay::PEM_get_string_X509($t{cert}));
	$t{cert_subject}    = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($t{cert}));

	if ($G::tls_cert && $G::tls_key) {
		$t{local_cert}            = Net::SSLeay::get_certificate($t{ssl});
		chomp($t{local_cert_x509} = Net::SSLeay::PEM_get_string_X509($t{local_cert}));
		$t{local_cert_subject}    = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($t{local_cert}));
	}

	return($t{active});
}

sub deprecate {
	my $message = shift;

	ptrans(12, "DEPRECATION WARNING: $message");
}

sub ptrans {
	my $c = shift;  # transaction flag
	my $m = shift;  # message to print
	my $b = shift;  # be brief in what we print
	my $a = shift;  # return the message in an array ref instead of printing
	my $o = $G::trans_fh_oh || \*STDOUT;
	my $f = '';

	return if (($G::hide_send          && int($c/10) == 2)  ||
	           ($G::hide_receive       && int($c/10) == 3)  ||
	           ($G::hide_informational && $c         == 11) ||
	           ($G::hide_all));

	# global option silent controls what we echo to the terminal
	# 0 - print everything
	# 1 - don't show anything until you hit an error, then show everything
	#     received after that (done by setting option to 0 on first error)
	# 2 - don't show anything but errors
	# >=3 - don't print anything
	if ($G::silent > 0) {
		return if ($G::silent >= 3);
		return if ($G::silent == 2 && $c%2 != 0);
		if ($G::silent == 1 && !$G::ptrans_seen_error) {
			if ($c%2 != 0) {
				return();
			} else {
				$G::ptrans_seen_error = 1;
			}
		}
	}

	# 1x is program messages
	# 2x is smtp send
	# 3x is smtp recv
	# x = 1 is info/normal
	# x = 2 is error
	# x = 3 dump output
	# program info
	if    ($c == 11) { $f = $G::no_hints_info ? '' : '==='; }
	# program error
	elsif ($c == 12) { $f = $G::no_hints_info ? '' : '***'; $o = $G::trans_fh_eh || \*STDERR; }
	# smtp send info
	elsif ($c == 21) { $f = $G::no_hints_send ? '' : ($G::link{tls}{active} ? ' ~>' : ' ->'); }
	# smtp send error
	elsif ($c == 22) { $f = $G::no_hints_send ? '' : ($G::link{tls}{active} ? '*~>' : '**>'); }
	# smtp send dump output
	elsif ($c == 23) { $f = $G::no_hints_send ? '' : '  >'; }
	# smtp recv info
	elsif ($c == 31) { $f = $G::no_hints_recv ? '' : ($G::link{tls}{active} ? '<~ ' : '<- '); }
	# smtp recv error
	elsif ($c == 32) { $f = $G::no_hints_recv ? '' : ($G::link{tls}{active} ? '<~*' : '<**'); }
	# smtp recv dump output
	elsif ($c == 33) { $f = $G::no_hints_recv ? '' : '<  '; }
	# something went unexpectedly
	else             { $f = '???'; }

	$f .= ' ' if ($f);

	if ($b) {
		# split to tmp list to prevent -w gripe
		my @t = split(/\n/ms, $m); $m = scalar(@t) . " lines sent";
	}
	$m =~ s/\n/\n$f/msg;

	if ($a) {
		$m = "$f$m";
		return([ split(/\n/, $m) ]);
	}
	else {
		print $o "$f$m\n";
	}
}

sub do_smtp_quit {
	my $exit = shift;
	my $err  = shift;

	# Ugh.  Because PIPELINING allows mail's and rcpt's send to be disconnected,
	# and possibly with a QUIT between them, we need to set a global "we have
	# told the server we quit already" flag to prevent double-quits
	return(1) if ($G::link{quit_sent});
	$G::link{quit_sent} = 1;

	$G::link{allow_lost_cxn} = 1;
	my $r = do_smtp_gen('QUIT', '221');
	$G::link{allow_lost_cxn} = 0;

	handle_disconnect($err) if ($G::link{lost_cxn});

	if ($exit) {
		teardown_link();
		exit $err;
	}

	return($r);
}

sub do_smtp_drop {
	ptrans(11, "Dropping connection");
	exit(0);
}

sub do_smtp_tls {
	my $e  = shift; # ehlo config hash

	# 0 = tls succeeded
	# 1 = tls not advertised
	# 2 = tls advertised and attempted negotiations failed
	if (!$e->{STARTTLS}) {
		return(1);
	} elsif (!do_smtp_gen("STARTTLS", '220')) {
		return(2);
	} elsif (!start_tls()) {
		ptrans(12, "TLS startup failed ($G::link{tls}{res})");
		return(2);
	}
	tls_post_start();

	return(0);
}

sub do_smtp_xclient {
	my $e = shift;

	# 0 - xclient succeeded normally
	# 1 - xclient not advertised
	# 2 - xclient advertised but not attempted, mismatch in requested attrs
	# 3 - xclient attempted but did not succeed
	if (!$e->{XCLIENT}) {
		return(1);
	}
	my @parts = ();
	foreach my $attr (keys %{$G::xclient{attr}}) {
		if (!$e->{XCLIENT}{$attr}) {
			return(2) if (!$G::xclient{no_verify});
		}
	}

	foreach my $string (@{$G::xclient{strings}}) {
		my $str = "XCLIENT " . $string;
		do_smtp_gen($str, '220') || return(3);
	}
	return(0);
}

# see xtext encoding in http://tools.ietf.org/html/rfc1891
sub to_xtext {
	my $string = shift;

	return join('', map { ($_ == 0x2b || $_ == 0x3d || $_ <= 0x20 || $_ >= 0xff)
		                   ? sprintf("+%02X", $_)
		                   : chr($_)
		                } (unpack("C*", $string)));
}

sub do_smtp_auth {
	my $e  = shift; # ehlo config hash
	my $at = shift; # auth type
	my $au = shift; # auth user
	my $ap = shift; # auth password

	return(1) if (!$e->{AUTH});
	return(3) if ($G::auth_unavailable);

	my $auth_attempted = 0; # set to true if we ever attempt auth

	foreach my $btype (@$at) {
		# if server doesn't support, skip type (may change in future)
		next if (!$e->{AUTH}{$btype});

		foreach my $type (@{$G::auth_map_t{'CRAM-MD5'}}) {
			if ($btype eq $type) {
				return(0) if (do_smtp_auth_cram($au, $ap, $type));
				$auth_attempted = 1;
			}
		}
		foreach my $type (@{$G::auth_map_t{'CRAM-SHA1'}}) {
			if ($btype eq $type) {
				return(0) if (do_smtp_auth_cram($au, $ap, $type));
				$auth_attempted = 1;
			}
		}
		foreach my $type (@{$G::auth_map_t{'DIGEST-MD5'}}) {
			if ($btype eq $type) {
				return(0) if (do_smtp_auth_digest($au, $ap, $type));
				$auth_attempted = 1;
			}
		}
		foreach my $type (@{$G::auth_map_t{'NTLM'}}) {
			if ($btype eq $type) {
				return(0) if (do_smtp_auth_ntlm($au, $ap, $type));
				$auth_attempted = 1;
			}
		}
		foreach my $type (@{$G::auth_map_t{'PLAIN'}}) {
			if ($btype eq $type) {
				return(0) if (do_smtp_auth_plain($au, $ap, $type));
				$auth_attempted = 1;
			}
		}
		foreach my $type (@{$G::auth_map_t{'LOGIN'}}) {
			if ($btype eq $type) {
				return(0) if (do_smtp_auth_login($au, $ap, $type));
				$auth_attempted = 1;
			}
		}
	}

	return $auth_attempted ? 4 : 2;
}

sub do_smtp_auth_ntlm {
	my $u  = shift; # auth user
	my $p  = shift; # auth password
	my $as = shift; # auth type (since NTLM might be SPA or MSN)
	my $r  = '';    # will store smtp response

	my $auth_string = "AUTH $as";
	do_smtp_gen($auth_string, '334') || return(0);

	my $d = db64(Authen::NTLM::ntlm());

	$auth_string = eb64($d);
	do_smtp_gen($auth_string, '334', \$r, '',
	            $G::auth_showpt ? "$d" : '',
	            $G::auth_showpt ? \&unencode_smtp : '') || return(0);

	$r =~ s/^....//; # maybe something a little better here?
	Authen::NTLM::ntlm_domain($G::auth_extras{DOMAIN});
	Authen::NTLM::ntlm_user($u);
	Authen::NTLM::ntlm_password($p);
	$d = db64(Authen::NTLM::ntlm($r));

	$auth_string = eb64($d);
	do_smtp_gen($auth_string, '235', \$r, '', $G::auth_showpt ? "$d" : '') || return(0);

	return(1);
}

sub do_smtp_auth_digest {
	my $u  = shift; # auth user
	my $p  = shift; # auth password
	my $as = shift; # auth string
	my $r  = '';    # will store smtp response
	my $e  = '';    # will store Authen::SASL errors
	my @digest_uri = ();

	if (exists($G::auth_extras{"DMD5-SERV-TYPE"})) {
		$digest_uri[0] = $G::auth_extras{"DMD5-SERV-TYPE"};
	} else {
		$digest_uri[0] = 'smtp';
	}
	if (exists($G::auth_extras{"DMD5-HOST"})) {
		$digest_uri[1] = $G::auth_extras{"DMD5-HOST"};
	} else {
		if ($G::link{type} eq 'socket-unix') {
			$digest_uri[1] = $G::link{sockfile};
			$digest_uri[1] =~ s|[^a-zA-Z0-9\.\-]|-|g;
		} elsif ($G::link{type} eq 'pipe') {
			$digest_uri[1] = $G::link{process};
			$digest_uri[1] =~ s|[^a-zA-Z0-9\.\-]|-|g;
		} else {
			$digest_uri[1] = $G::link{server};
		}
	}
	if (exists($G::auth_extras{"DMD5-SERV-NAME"})) {
		# There seems to be a hole in the Authen::SASL interface where there's
		# no option to directory provide the digest-uri serv-name.  But we can
		# trick it into using the value we want by tacking it onto the end of host
		$digest_uri[1] .= '/' . $G::auth_extras{"DMD5-SERV-NAME"};
	}

	my $auth_string = "AUTH $as";
	do_smtp_gen($auth_string, '334', \$r, '', '', $G::auth_showpt ? \&unencode_smtp : '')
		|| return(0);

	$r =~ s/^....//; # maybe something a little better here?
	$r = db64($r);

	my $callbacks = { user => $u, pass => $p };
	if (exists($G::auth_extras{REALM})) {
		$callbacks->{realm} = $G::auth_extras{REALM};
	}

	my $sasl = Authen::SASL->new(
		debug     => 1,
		mechanism => 'DIGEST-MD5',
		callback  => $callbacks,
	);
	my $sasl_client = $sasl->client_new(@digest_uri);

	# Force the DIGEST-MD5 session to use qop=auth.  I'm open to exposing this setting
	# via some swaks options, but I don't know enough about the protocol to just guess
	# here.  I do know that letting it auto-negotiate didn't work in my reference
	# environment.  sendmail advertised auth,auth-int,auth-conf, but when Authen::SASL
	# chose auth-int the session would fail (server would say auth succeeded, but then
	# immediately terminate my session when I sent MAIL).  My reference client
	# (Mulberry) always sent auth, and indeed forcing swaks to auth also seems to work.
	# If anyone out there knows more about this please let me know.
	$sasl_client->property('maxssf' => 0);

	$auth_string = $sasl_client->client_step($r);
	if ($e = $sasl_client->error()) {
		ptrans('12', "Error received from Authen::SASL sub-system: $e");
		return(0);
	}

	do_smtp_gen(eb64($auth_string), '334', \$r, '',
	                 $G::auth_showpt ? "$auth_string" : '',
	                 $G::auth_showpt ? \&unencode_smtp : '')
		|| return(0);
	$r =~ s/^....//; # maybe something a little better here?
	$r = db64($r);

	$auth_string = $sasl_client->client_step($r);
	if ($e = $sasl_client->error()) {
		ptrans('12', "Canceling SASL exchange, error received from Authen::SASL sub-system: $e");
		$auth_string = '*';
	}
	#do_smtp_gen(eb64($auth_string), '235', \$r, '', $G::auth_showpt ? "$auth_string" : '')
	do_smtp_gen($auth_string, '235', \$r, '', $auth_string)
		|| return(0);
	if ($e = $sasl_client->error()) {
		ptrans('12', "Error received from Authen::SASL sub-system: $e");
		return(0);
	}
	return(0) if (!$sasl_client->is_success());

	return(1);
}

# This can handle both CRAM-MD5 and CRAM-SHA1
sub do_smtp_auth_cram {
	my $u  = shift; # auth user
	my $p  = shift; # auth password
	my $as = shift; # auth string
	my $r  = '';    # will store smtp response

	my $auth_string = "AUTH $as";
	do_smtp_gen($auth_string, '334', \$r, '', '', $G::auth_showpt ? \&unencode_smtp : '')
			|| return(0);

	$r =~ s/^....//; # maybe something a little better here?
	# specify which type of digest we need based on $as
	my $d = get_digest($p, $r, ($as =~ /-SHA1$/ ? 'sha1' : 'md5'));
	$auth_string = eb64("$u $d");

	do_smtp_gen($auth_string, '235', undef, '', $G::auth_showpt ? "$u $d" : '') || return(0);
	return(1);
}

sub do_smtp_auth_login {
	my $u  = shift; # auth user
	my $p  = shift; # auth password
	my $as = shift; # auth string

	do_smtp_gen("AUTH $as", '334', undef, '', '', $G::auth_showpt ? \&unencode_smtp : '')
		|| return(0);
	do_smtp_gen(eb64($u),   '334', undef, '', $G::auth_showpt ? $u : '', $G::auth_showpt ? \&unencode_smtp : '')
		|| return(0);
	do_smtp_gen(eb64($p),   '235', undef, '',
	            $G::auth_showpt ? ($G::auth_hidepw || $p) : eb64($G::auth_hidepw || $p))
		|| return(0);
	return(1);
}

sub do_smtp_auth_plain {
	my $u  = shift; # auth user
	my $p  = shift; # auth password
	my $as = shift; # auth string

	return(do_smtp_gen("AUTH $as " . eb64("\0$u\0$p"), '235', undef, '',
	                   $G::auth_showpt ? "AUTH $as \\0$u\\0" . ($G::auth_hidepw || $p)
	                   : "AUTH $as " . eb64("\0$u\0" . ($G::auth_hidepw || $p))));
}

sub do_smtp_helo {
	my $h = shift;  # helo string to use
	my $e = shift;  # this is a hashref that will be populated w/ server options
	my $p = shift;  # protocol for the transaction
	my $r = '';     # this'll be populated by do_smtp_gen

	if ($p eq 'esmtp' || $p eq 'lmtp') {
		my $l = $p eq 'lmtp' ? "LHLO" : "EHLO";
		if (do_smtp_gen("$l $h", '250', \$r)) {
			# There's not a standard structure for the $e hashref, each
			# key is stored in the manner that makes the most sense
			foreach my $l (split(/\n/, $r)) {
				$l =~ s/^....//;
				if ($l =~ /^AUTH=?(.*)$/) {
					map { $e->{AUTH}{uc($_)} = 1 } (split(' ', $1));
				} elsif ($l =~ /^XCLIENT\s*(.*?)$/) {
					$e->{XCLIENT} = {}; # prime the pump in case no attributes were advertised
					map { $e->{XCLIENT}{uc($_)} = 1 } (split(' ', $1));
				} elsif ($l =~ /^STARTTLS$/) {
					$e->{STARTTLS} = 1;
				} elsif ($l =~ /^PIPELINING$/) {
					$e->{PIPELINING} = 1;
					$G::pipeline_adv = 1;
				} elsif ($l =~ /^PRDR$/) {
					$e->{PRDR} = 1;
				}
			}
			return(1);
		}
	}
	if ($p eq 'esmtp' || $p eq 'smtp') {
		return(do_smtp_gen("HELO $h", '250'));
	}

	return(0);
}

sub do_smtp_mail {
	my $e = shift;  # ehlo response
	my $a = shift;  # from address
	my $m = "MAIL FROM:<$a>";

	if ($G::prdr) {
		if (!$e->{PRDR}) {
			return(1); # PRDR was required but was not advertised.  Return error and let caller handle it
		} else {
			$m .= " PRDR";
		}
	}

	transact(cxn_string => $m, expect => '250', defer => 1, fail_callback => \&smtp_mail_callback);

	return(0); # the callback handles failures, so just return here
}

# this only really needs to exist until I figure out a clever way of making
# do_smtp_quit the callback while still preserving the exit codes
sub smtp_mail_callback {
	do_smtp_quit(1, 23);
}

sub do_smtp_rcpt {
	my $m = shift;  # string of comma separated recipients
	my $f = 0;      # The number of failures we've experienced
	my @a = split(/,/, $m);
	$G::smtp_rcpt_total = scalar(@a);

	foreach my $addr (@a) {
		transact(cxn_string => 'RCPT TO:<' . $addr . '>', expect => '250', defer => 1,
		         fail_callback => \&smtp_rcpt_callback);
	}

	return(1); # the callback handles failures, so just return here
}

sub smtp_rcpt_callback {
	# record that a failure occurred
	$G::smtp_rcpt_failures++;

	# if the number of failures is the same as the total rcpts (if every rcpt rejected), quit.
	if ($G::smtp_rcpt_failures == $G::smtp_rcpt_total) {
		do_smtp_quit(1, 24);
	}
}

sub do_smtp_data {
	my $m = shift; # string to send
	my $b = shift; # be brief in the data we send
	my $r  = '';   # will store smtp response
	my $e = $G::prdr ? '(250|353)' : '250';

	my $calls = $G::smtp_rcpt_total - $G::smtp_rcpt_failures;
	my $ok    = transact(cxn_string => $m, expect => $e, summarize_output => $b, return_text => \$r);

	# now be a little messy - lmtp is not a lockstep after data - we need to
	# listen for as many calls as we had accepted recipients
	if ($G::protocol eq 'lmtp') {
		foreach my $c (1..($calls-1)) { # -1 because we already got 1 above
			$ok += transact(cxn_string => undef, expect => '250');
		}
	} elsif ($G::protocol eq 'esmtp' && $G::prdr && $r =~ /^353 /) {
		foreach my $c (1..$calls) {
			transact(cxn_string => undef, expect => '250'); # read the status of each recipient off the wire
		}
		$ok = transact(cxn_string => undef, expect => '250'); # PRDR has an overall acceptance string, read it here and use it as th success indicator
	}
	return($ok)
}

sub do_smtp_gen {
	my $m = shift; # string to send (if empty, we won't send anything, only read)
	my $e = shift; # String we're expecting to get back
	my $p = shift; # if this is a scalar ref, assign the server return string to it
	my $b = shift; # be brief in the data we print
	my $x = shift; # if this is populated, print this instead of $m
	my $c = shift; # if this is a code ref, call it on the return value before printing it
	my $n = shift; # if true, when the data is sent over the wire, it will not have \r\n appended to it
	my $r = shift; # if true, we won't try to ready a response from the server

	return transact(cxn_string       => $m, expect           => $e, return_text    => $p,
	                summarize_output => $b, show_string      => $x, print_callback => $c,
	                no_newline       => $n, no_read_response => $r,
	               );
}

sub do_smtp_proxy {
	my $send       = undef;
	my $print      = undef;
	my $no_newline = 0;

	if ($G::proxy{version} == 2) {
		$send = pack("W[12]", 0x0D, 0x0A,0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A);
		if ($G::proxy{raw}) {
			$send .= $G::proxy{raw};
		} else {
			# byte 13
			#    4 bits = version (required to be 0x2)
			#    4 bits = command (0x2 = LOCAL, 0x1 = PROXY)
			$send .= pack("W", 0x20 + ($G::proxy{attr}{command} eq 'LOCAL' ? 0x02 : 0x01));
			if ($G::proxy{attr}{command} eq 'LOCAL') {
				# the protocol byte (14, including family and protocol) are ignored with local.  Set to zeros
				$send .= pack("W", 0x00);
				# and, additionally, if we're local, there isn't going to be any address size (bytes 15 and 16)
				$send .= pack("W", 0x00);
			} else {
				# byte 14
				#    4 bits = address family (0x0 = AF_UNSPEC, 0x1 = AF_INET, 0x2 = AF_INET6, 0x3 = AF_UNIX)
				#    4 bits = transport protocol (0x0 = UNSPEC, 0x1 = STREAM, 0x2 = DGRAM)
				my $byte = 0;
				if ($G::proxy{attr}{family} eq 'AF_UNSPEC') {
					$byte = 0x00;
				} elsif ($G::proxy{attr}{family} eq 'AF_INET') {
					$byte = 0x10;
				} elsif ($G::proxy{attr}{family} eq 'AF_INET6') {
					$byte = 0x20;
				} elsif ($G::proxy{attr}{family} eq 'AF_UNIX') {
					$byte = 0x30;
				}
				if ($G::proxy{attr}{protocol} eq 'UNSPEC') {
					$byte += 0x0;
				} elsif ($G::proxy{attr}{protocol} eq 'STREAM') {
					$byte += 0x1;
				} elsif ($G::proxy{attr}{protocol} eq 'DGRAM') {
					$byte += 0x2;
				}
				$send .= pack("W", $byte);

				# network portion (bytes 17+)
				my $net = pack_ip($G::proxy{attr}{source})
				        . pack_ip($G::proxy{attr}{dest})
				        . pack("n", $G::proxy{attr}{source_port})
				        . pack("n", $G::proxy{attr}{dest_port});
				$send  .= pack("n", length($net)) . $net; # add bytes 15+16 (length of network portion) plus the network portion
			}
		}

		# version 2 is binary, so uuencode it before printing.  Also, version 2 REQUIREs that you not send \r\n after it down the wire
		$print      = eb64($send);
		$no_newline = 1;
	} else {
		if ($G::proxy{raw}) {
			$send = "PROXY $G::proxy{raw}";
		} else {
			$send = join(' ', 'PROXY', $G::proxy{attr}{family}, $G::proxy{attr}{source}, $G::proxy{attr}{dest}, $G::proxy{attr}{source_port}, $G::proxy{attr}{dest_port});
		}
	}

	do_smtp_gen($send,       # to be send over the wire
	            '220',       # response code indicating success
	            undef,       # the return string from the server (don't need it)
	            0,           # do not be brief when printing
	            $print,      # if populated, print this instead of $send
	            undef,       # don't want a post-processing callback
	            $no_newline, # if true, don't add \r\n to the end of $send when sent over the wire
	            1,           # don't read a response - we only want to send the value
	);
}

# no special attempt made at verifying, on purpose
sub pack_ip {
	my $ip = shift;

	if ($ip =~ /:/) {
		# this is the stupidest piece of code ever.  Please tell me all the fun ways it breaks
		my @pieces = split(/:/, $ip);
		my $p;
		shift(@pieces) if ($pieces[0] eq '' && $pieces[1] eq ''); #
		foreach my $word (@pieces) {
			if ($word eq '') {
				foreach my $i (0..(8-scalar(@pieces))) {
					$p .= pack("n", 0);
				}
			} else {
				$p .= pack("n", hex($word));
			}
		}
		return($p);
	} else {
		return(pack("W*", split(/\./, $ip)));
	}
}

# If we detect that the other side has gone away when we were expecting
# to still be reading, come in here to error and die.  Abstracted because
# the error message will vary depending on the type of connection
sub handle_disconnect {
	my $e = shift || 6; # this is the code we will exit with
	if ($G::link{type} eq 'socket-inet') {
		ptrans(12, "Remote host closed connection unexpectedly.");
	} elsif ($G::link{type} eq 'socket-unix') {
		ptrans(12, "Socket closed connection unexpectedly.");
	} elsif ($G::link{type} eq 'pipe') {
		ptrans(12, "Child process closed connection unexpectedly.");
	}
	exit($e);
}

sub flush_send_buffer {
	my $s = $G::link{type} eq 'pipe' ? $G::link{sock}->{wr} : $G::link{sock};
	return if (!$G::send_buffer);
	if ($G::link{tls}{active}) {
		my $res = Net::SSLeay::write($G::link{tls}{ssl}, $G::send_buffer);
	} else {
		print $s $G::send_buffer;
	}
	ptrans(23, hdump($G::send_buffer)) if ($G::show_raw_text);
	$G::send_buffer = '';
}

sub send_data {
	my $d   = shift;      # data to write
	my $nnl = shift || 0; # if true, don't add a newline (needed for PROXY v2 support)
	$G::send_buffer .= $d . ($nnl ? '' : "\r\n");
}

sub recv_line {
	# Either an IO::Socket obj or a FH to my child - the thing to read from
	my $s = $G::link{type} eq 'pipe' ? $G::link{sock}->{re} : $G::link{sock};
	my $r = undef;
	my $t = undef;
	my $c = 0;

	while ($G::recv_buffer !~ m|\n|si) {
		last if (++$c > 1000); # Maybe I'll remove this once I trust this code more
		if ($G::link{tls}{active}) {
			$t = Net::SSLeay::read($G::link{tls}{ssl});
			return($t) if (!defined($t));

			# THIS CODE COPIED FROM THE ELSE BELOW.  Found I could trip this condition
			# by having the server sever the connection but not have swaks realize the
			# connection was gone.  For instance, send a PIPELINE mail that includes a
			# "-q rcpt".  There was a bug in swaks that made it try to send another quit
			# later, thus tripping this "1000 reads" error (but only in TLS).
			# Short term: add line below to prevent these reads
			# Short Term: fix the "double-quit" bug
			# Longer term: test to see if remote side closed connection

			# the above line should be good enough but it isn't returning
			# undef for some reason.  I think heuristically it will be sufficient
			# to just look for an empty packet (I hope.  gulp).  Comment out the
			# following line if your swaks seems to be saying that it lost connection
			# for no good reason.  Then email me about it.
			return(undef()) if (!length($t));
		} elsif ($G::link{type} eq 'pipe') {
			# XXX in a future release see if I can get read() or equiv to work on a pipe
			$t = <$s>;
			return($t) if (!defined($t));

			# THIS CODE COPIED FROM THE ELSE BELOW.
			# the above line should be good enough but it isn't returning
			# undef for some reason.  I think heuristically it will be sufficient
			# to just look for an empty packet (I hope.  gulp).  Comment out the
			# following line if your swaks seems to be saying that it lost connection
			# for no good reason.  Then email me about it.
			return(undef()) if (!length($t));
		} else {
			# if you're having problems with reads, swap the comments on the
			# the following two lines
			my $recv_r = recv($s, $t, 8192, 0);
			#$t = <$s>;
			return($t) if (!defined($t));

			# the above line should be good enough but it isn't returning
			# undef for some reason.  I think heuristically it will be sufficient
			# to just look for an empty packet (I hope.  gulp).  Comment out the
			# following line if your swaks seems to be saying that it lost connection
			# for no good reason.  Then email me about it.
			return(undef()) if (!length($t));

			#print "\$t = $t (defined = ", defined($t) ? "yes" : "no",
			#      "), \$recv_r = $recv_r (", defined($recv_r) ? "yes" : "no", ")\n";
		}
		$G::recv_buffer .= $t;
		ptrans(33, hdump($t)) if ($G::show_raw_text);
	}

	if ($c >= 1000) {
		# If you saw this in the wild, I'd love to hear more about it
		# at proj-swaks@jetmore.net
		ptrans(12, "In recv_line, hit loop counter.  Continuing in unknown state");
	}

	# using only bare newlines is bound to cause me problems in the future
	# but it matches the expectation we've already been using.  All we can
	# do is hone in on the proper behavior iteratively.
	if ($G::recv_buffer =~ s|^(.*?\n)||si) {
		$r = $1;
	} else {
		ptrans(12, "I'm in an impossible state");
	}

	$r =~ s|\r||msg;
	return($r);
}

# any request which has immediate set will be checking the return code.
# any non-immediate request will handle results through fail_callback().
# therefore, only return the state of the last transaction attempted,
# which will always be immediate
# defer            - if true, does not require immediate flush when pipelining
# cxn_string       - What we will be sending the server. If undefined, we won't send, only read
# no_read_response - if true, we won't read a response from the server, we'll just send
# summarize_output - if true, don't print to terminal everything we send to server
# no_newline       - if true, do not append \r\n to the data we send to server
# return_text      - should be scalar ref.  will be assigned reference to what was returned from server
# print_callback   - if present and a code reference, will be called with server return data for printing to terminal
# fail_callback    - if present and a code reference, will be called on failure
sub transact {
	my %h        = @_; # this is an smtp transaction element
	my $ret      = 1;  # this is our return value
	my @handlers = (); # will hold any fail_handlers we need to run
	my $time     = ''; # used in time lapse calculations

	push(@G::pending_send, \%h); # push onto send queue
	if (!($G::pipeline && $G::pipeline_adv) || !$h{defer}) {

		if ($G::show_time_lapse eq 'hires') {
			$time = [Time::HiRes::gettimeofday()];
		}
		elsif ($G::show_time_lapse eq 'integer') {
			$time = time();
		}

		while (my $i = shift(@G::pending_send)) {
			if (defined($i->{cxn_string})) {
				ptrans(21, $i->{show_string} || $i->{cxn_string}, $i->{summarize_output});
				send_data($i->{cxn_string}, $i->{no_newline});
			}
			push(@G::pending_recv, $i) if (!$i->{no_read_response});
		}
		flush_send_buffer();

		do_smtp_drop() if ($G::drop_before_read);

		while (my $i = shift(@G::pending_recv)) {
			my $buff = '';
			eval {
				local $SIG{'ALRM'} = sub {
					$buff = "Timeout ($G::link{timeout} secs) waiting for server response";
					die;
				};
				alarm($G::link{timeout});
				while ($buff !~ /^\d\d\d /m) {
					my $l = recv_line();
					$buff .= $l;
					if (!defined($l)) {
						$G::link{lost_cxn} = 1;
						last;
					}
				}
				chomp($buff);
				alarm(0);
			};

			if ($G::show_time_lapse eq 'hires') {
				$time = sprintf("%0.03f", Time::HiRes::tv_interval($time, [Time::HiRes::gettimeofday()]));
				ptrans(11, "response in ${time}s");
				$time = [Time::HiRes::gettimeofday()];
			} elsif ($G::show_time_lapse eq 'integer') {
				$time = time() - $time;
				ptrans(11, "response in ${time}s");
				$time = time();
			}

			${$i->{return_text}} = $buff;
			$buff = &{$i->{print_callback}}($buff) if (ref($i->{print_callback}) eq 'CODE');
			my $ptc;
			($ret,$ptc) = $buff !~ /^$i->{expect} /m ? (0,32) : (1,31);
			ptrans($ptc, $buff) if ($buff);
			if ($G::link{lost_cxn}) {
				if ($G::link{allow_lost_cxn}) {
					# this means the calling code wants to handle a lost cxn itself
					return($ret);
				} else {
					# if caller didn't want to handle, we'll handle a lost cxn ourselves
					handle_disconnect();
				}
			}
			if (!$ret && ref($i->{fail_callback}) eq 'CODE') {
				push(@handlers, $i->{fail_callback});
			}
		}
	}
	foreach my $h (@handlers) { &{$h}(); }
	return($ret);
}

# a quick-and-dirty hex dumper.  Currently used by --show-raw-text
sub hdump {
	my $r = shift;
	my $c = 0;  # counter
	my $i = 16; # increment value
	my $b;      # buffer

	while (length($r) && ($r =~ s|^(.{1,$i})||smi)) {
		my $s = $1; # $s will be the ascii string we manipulate for display
		my @c = map { ord($_); } (split('', $s));
		$s =~ s|[^\x21-\x7E]|.|g;

		my $hfs = ''; # This is the hex format string for printf
		for (my $hc = 0; $hc < $i; $hc++) {
			$hfs .= ' ' if (!($hc%4));
			if ($hc < scalar(@c)) { $hfs .= '%02X '; } else { $hfs .= '   '; }
		}

		$b .= sprintf("%04d:$hfs   %-16s\n", $c, @c, $s);
		$c += $i;
	}
	chomp($b); # inelegant remnant of hdump's previous life
	return($b)
}

sub unencode_smtp {
	my $t = shift;

	my @t = split(' ', $t, 2);
	if ($t[1] =~ /\s/) {
		# very occasionally we can have a situation where a successful response will
		# be b64 encoded, while an error will not be.  Try to tell the difference.
		return($t);
	} else {
		return("$t[0] " . db64($t[1]));
	}
}

sub obtain_from_netrc {
	my $field = shift;
	my $login = shift;

	return if !avail('netrc');

	if (my $netrc = Net::Netrc->lookup($G::link{server}, defined($login) ? $login : ())) {
		return($netrc->$field);
	}

	return;
}

sub interact {
	my $prompt     = shift;
	my $regexp     = shift;
	my $hide_input = shift;
	my $response   = '';

	do {
		print $prompt;
		if (!$hide_input || !$G::protect_prompt || $G::interact_method eq 'default') {
			chomp($response = <STDIN>);
		} else {
			if ($^O eq 'MSWin32') {
				#if ($G::interact_method eq "win32-console" ||
				#   (!$G::interact_method && load("Win32::Console")))
				#{
				#    Couldn't get this working in the time I wanted to devote to it
				#}
				if ($G::interact_method eq "win32-readkey" ||
					 (!$G::interact_method && load("Term::ReadKey")))
				{
					$G::interact_method ||= "win32-readkey";
					# the trick to replace input w/ '*' doesn't work on Win32
					# Term::ReadKey, so just use it as an stty replacement
					ReadMode('noecho');
					# need to think about this on windows some more
					#local $SIG{INT} = sub { ReadMode('restore'); };
					chomp($response = <STDIN>);
					ReadMode('restore');
					print "\n";
				} else {
					$G::interact_method ||= "default";
					chomp($response = <STDIN>);
				}
			} else {
				if ($G::interact_method eq "unix-readkey" || (!$G::interact_method && load("Term::ReadKey"))) {
					$G::interact_method ||= "unix-readkey";
					my @resp = ();
					ReadMode('raw');
					#local $SIG{INT} =
					# reevaluate this code - what happens if del is first char we press?
					while ((my $kp = ReadKey(0)) ne "\n") {
						my $kp_num = ord($kp);
						if($kp_num == 127 || $kp_num == 8) {
							next if (!scalar(@resp));
							pop(@resp);
							print "\b \b";
						} elsif($kp_num >= 32) {
							push(@resp, $kp);
							print "*";
						}
					}
					ReadMode('restore');
					print "\n";
					$response = join('', @resp);
				} elsif ($G::interact_method eq "unix-stty" || (!$G::interact_method && open(STTY, "stty -a |"))) {
					$G::interact_method ||= "unix-stty";
					{ my $foo = join('', <STTY>); }
					system('stty', '-echo');
					chomp($response = <STDIN>);
					system('stty', 'echo');
					print "\n";
				} else {
					$G::interact_method ||= "default";
					chomp($response = <STDIN>);
				}
			}
		}
	} while ($regexp ne 'SKIP' && $response !~ /$regexp/);

	return($response);
}

sub get_messageid {
	if (!$G::message_id) {
		my @time = localtime();
		$G::message_id = sprintf("%04d%02d%02d%02d%02d%02d.%06d\@%s",
		                         $time[5]+1900, $time[4]+1, $time[3], $time[2], $time[1], $time[0],
		                         $$, get_hostname());
	}

	return($G::message_id);
}

sub get_hostname {
	# in some cases hostname returns value but gethostbyname doesn't.
	return("") if (!avail("hostname"));

	my $h = hostname();
	return("") if (!$h);

	my $l = (gethostbyname($h))[0];
	return($l || $h);
}

sub get_server {
	my $addr   = shift;
	my $pref   = -1;
	my $server = "localhost";

	if ($addr =~ /\@?\[(\d+\.\d+\.\d+\.\d+)\]$/) {
		# handle automatic routing of domain literals (user@[1.2.3.4])
		return($1);
	} elsif ($addr =~ /\@?\#(\d+)$/) {
		# handle automatic routing of decimal domain literals (user@#16909060)
		$addr = $1;
		return(($addr/(2**24))%(2**8) . '.' . ($addr/(2**16))%(2**8) . '.' .
		       ($addr/(2**8))%(2**8)  . '.' . ($addr/(2**0))%(2**8));
	}

	if (!avail("dns")) {
		ptrans(12, avail_str("dns"). ".  Using $server as mail server");
		return($server);
	}
	my $res = Net::DNS::Resolver->new();

	$addr =~ s/^.*\@([^\@]*)$/$1/;
	return($server) if (!$addr);
	$server = $addr;

	my @mx = mx($res, $addr);
	foreach my $rr (sort { $a->preference <=> $b->preference } @mx) {
		if ($G::link{force_ipv4}) {
			if ($res->query($rr->exchange, 'A')) {
				$server = $rr->exchange;
				last;
			}
		} elsif ($G::link{force_ipv6}) {
			if ($res->query($rr->exchange, 'AAAA') || $res->query($rr->exchange, 'A6')) {
				$server = $rr->exchange;
				last;
			}
		} else {
			# this is the old default behavior.  Take the best priority MX, no matter what.
			$server = $rr->exchange;
			last;
		}
	}
	return($server);
}

sub load {
	my $m = shift;

	return $G::modules{$m} if (exists($G::modules{$m}));
	eval("use $m");
	return $G::modules{$m} = $@ ? 0 : 1;
}

# Currently this is just an informational string - it's set on both
# success and failure.  It currently has four output formats (supported,
# supported but not optimal, unsupported, unsupported and missing optimal)
sub avail_str { return $G::dependencies{$_[0]}{errstr}; }

sub avail {
	my $f = shift; # this is the feature we want to check support for (auth, tls)
	my $s = \%G::dependencies;

	# return immediately if we've already tested this.
	return($s->{$f}{avail}) if (exists($s->{$f}{avail}));

	$s->{$f}{req_failed} = [];
	$s->{$f}{opt_failed} = [];
	foreach my $m (@{$s->{$f}{req}}) {
		push(@{$s->{$f}{req_failed}}, $m) if (!load($m));
	}
	foreach my $m (@{$s->{$f}{opt}}) {
		push(@{$s->{$f}{opt_failed}}, $m) if (!load($m));
	}

	if (scalar(@{$s->{$f}{req_failed}})) {
		$s->{$f}{errstr} = "$s->{$f}{name} not available: requires " . join(', ', @{$s->{$f}{req_failed}});
		if (scalar(@{$s->{$f}{opt_failed}})) {
			$s->{$f}{errstr} .= ".  Also missing optimizing " . join(', ', @{$s->{$f}{opt_failed}});
		}
		return $s->{$f}{avail} = 0;
	} else {
		if (scalar(@{$s->{$f}{opt_failed}})) {
			$s->{$f}{errstr} = "$s->{$f}{name} supported, but missing optimizing " .
			                   join(', ', @{$s->{$f}{opt_failed}});
		} else {
			$s->{$f}{errstr} = "$s->{$f}{name} supported";
		}
		return $s->{$f}{avail} = 1;
	}
}

sub get_digest {
	my $secr = shift;
	my $chal = shift;
	my $type = shift || 'md5';
	my $ipad = chr(0x36) x 64;
	my $opad = chr(0x5c) x 64;

	if ($chal !~ /^</) {
		chomp($chal = db64($chal));
	}

	if (length($secr) > 64) {
		if ($type eq 'md5') {
			$secr = Digest::MD5::md5($secr);
		} elsif ($type eq 'sha1') {
			$secr = Digest::SHA::sha1($secr);
		}
	} else {
		$secr .= chr(0) x (64 - length($secr));
	}

	my $digest = $type eq 'md5' ? Digest::MD5::md5_hex(($secr ^ $opad), Digest::MD5::md5(($secr ^ $ipad), $chal))
	                            : Digest::SHA::sha1_hex(($secr ^ $opad), Digest::SHA::sha1(($secr ^ $ipad), $chal));
	return($digest);
}

sub test_support {
	my $return = shift;
	my $lines  = [];
	my $s      = \%G::dependencies;

	foreach my $act (sort { $s->{$a}{name} cmp $s->{$b}{name} } keys %$s) {
		if ($return) {
			push(@$lines, @{ptrans(avail($act) ? 11 : 12, avail_str($act), undef, 1)});
		}
		else {
			ptrans(avail($act) ? 11 : 12, avail_str($act));
		}
	}

	if ($return) {
		return($lines);
	}
}

sub time_to_seconds {
	my $t = shift;

	if ($t !~ /^(\d+)([hms])?$/i) {
		ptrans(12, 'Unknown timeout format \'' . $t . '\'');
		exit(1);
	} else {
		my $r = $1;
		my $u = lc($2);
		if ($u eq 'h') {
			return($r * 3600);
		} elsif ($u eq 'm') {
			return($r * 60);
		} else {
			return($r);
		}
	}
}

sub load_dependencies {
	%G::dependencies = (
		auth            => { name => "Basic AUTH",               opt => ['MIME::Base64'],
		                                                         req => []                    },
		auth_cram_md5   => { name => "AUTH CRAM-MD5",            req => ['Digest::MD5']       },
		auth_cram_sha1  => { name => "AUTH CRAM-SHA1",           req => ['Digest::SHA']       },
		auth_ntlm       => { name => "AUTH NTLM",                req => ['Authen::NTLM']      },
		auth_digest_md5 => { name => "AUTH DIGEST-MD5",          req => ['Authen::SASL']      },
		dns             => { name => "MX Routing",               req => ['Net::DNS']          },
		netrc           => { name => 'Netrc Credentials',        req => ['Net::Netrc']        },
		tls             => { name => "TLS",                      req => ['Net::SSLeay']       },
		pipe            => { name => "Pipe Transport",           req => ['IPC::Open2']        },
		socket          => { name => "Socket Transport",         req => ['IO::Socket']        },
		ipv6            => { name => "IPv6",                     req => ['IO::Socket::INET6'] },
		date_manip      => { name => "Date Manipulation",        req => ['POSIX']             },
		hostname        => { name => "Local Hostname Detection", req => ['Sys::Hostname']     },
		hires_timing    => { name => "High Resolution Timing",   req => ['Time::HiRes']       },
	);
}

sub process_opt_silent {
	my $opt = shift;
	my $arg = shift;

	if ($arg =~ /^[123]$/) {
		return($arg);
	}
	else {
		return(1);
	}
}

sub get_option_struct {
	use constant {
		OP_ARG_OPT     => 0x01, # option takes an optional argument
		OP_ARG_REQ     => 0x02, # option takes a required argument
		OP_ARG_NONE    => 0x04, # option does not take any argument (will return boolean)
		OP_FROM_PROMPT => 0x08, # option prompts for an argument if none provided
		OP_FROM_FILE   => 0x10, # option treats arg of '-' to mean 'read from stdin' (no prompt)
		OP_DEPRECATED  => 0x20, # This option is deprecated
		OP_SENSITIVE   => 0x40, # indicates that if prompted for, the argument should be masked (see --protect-prompt)
	};

	@G::raw_option_data = (
		# location of config file.  Note that the "config" option is processed differently
		# than any other option because it needs to be processed before standard option processing
		# can happen.  We still define it here to make Getopt::Long and fetch_args() happy.
		{ opts    => ['config'],                                           suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'config_file',                                        type   => 'scalar', },
		# envelope-(f)rom address
		{ opts    => ['from', 'f'],                                        suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'From: ',                                             match  => '^.*$',
		  okey    => 'mail_from',                                          type   => 'scalar', },
		# envelope-(t)o address
		{ opts    => ['to', 't'],                                          suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'To: ',                                               match  => '^.+$',
		  okey    => 'mail_to',                                            type   => 'scalar', },
		# (h)elo string
		{ opts    => ['helo', 'ehlo', 'lhlo', 'h'],                        suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Helo: ',                                             match  => '^.*$',
		  okey    => 'mail_helo',                                          type   => 'scalar', },
		# (s)erver to use
		{ opts    => ['server', 's'],                                      suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Server: ',                                           match  => '^.*$',
		  okey    => 'mail_server',                                        type   => 'scalar', },
		# force ipv4 only
		{ opts    => ['4'],                                                suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'force_ipv4',                                         type   => 'scalar', },
		# force ipv6 only
		{ opts    => ['6'],                                                suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'force_ipv6',                                         type   => 'scalar', },
		# copy MX/routing from another domain
		{ opts    => ['copy-routing'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'copy_routing',                                       type   => 'scalar', },
		# (p)ort to use
		{ opts    => ['port', 'p'],                                        suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Port: ',                                             match  => '^\w+$',
		  okey    => 'mail_port',                                          type   => 'scalar', },
		# protocol to use (smtp, esmtp, lmtp)
		{ opts    => ['protocol'],                                         suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'mail_protocol',                                      type   => 'scalar', },
		# (d)ata portion ('\n' for newlines)
		{ opts    => ['data', 'd'],                                        suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT|OP_FROM_FILE,
		  prompt  => 'Data: ',                                             match  => '^.*$',
		  okey    => 'mail_data',                                          type   => 'scalar', },
		# use the --dump text as default body
		{ opts    => ['dump-as-body', 'dab'],                              suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'dump_as_body',                                       type   => 'scalar', },
		# implies --dump-as-body; forces raw passwords to be used
		{ opts    => ['dump-as-body-shows-password', 'dabsp'],             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'dab_sp',                                             type   => 'scalar', },
		# timeout for each trans (def 30s)
		{ opts    => ['timeout'],                                          suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Timeout: ',                                          match  => '^\d+[hHmMsS]?$',
		  okey    => 'timeout',                                            type   => 'scalar', },
		# (q)uit after
		{ opts    => ['quit-after', 'quit', 'q'],                          suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'quit_after',                                         type   => 'scalar', },
		# drop after (don't quit, just drop)
		{ opts    => ['drop-after', 'drop', 'da'],                         suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'drop_after',                                         type   => 'scalar', },
		# drop after send (between send and read)
		{ opts    => ['drop-after-send', 'das'],                           suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'drop_after_send',                                    type   => 'scalar', },
		# do (n)ot print data portion
		{ opts    => ['suppress-data', 'n'],                               suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'suppress_data',                                      type   => 'scalar', },
		# force auth, exit if not supported
		{ opts    => ['auth', 'a'],                                        suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'auth',                                               type   => 'scalar', },
		# user for auth
		{ opts    => ['auth-user', 'au'],                                  suffix => ':s',
		  cfgs    => OP_ARG_OPT, # we dynamically change this later
		  okey    => 'auth_user',                                          type   => 'scalar', },
		# pass for auth
		{ opts    => ['auth-password', 'ap'],                              suffix => ':s',
		  cfgs    => OP_ARG_OPT|OP_SENSITIVE, # we dynamically change this later
		  okey    => 'auth_pass',                                          type   => 'scalar', },
		# auth type map
		{ opts    => ['auth-map', 'am'],                                   suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'auth_map',                                           type   => 'scalar', },
		# extra, authenticator-specific options
		{ opts    => ['auth-extra', 'ae'],                                 suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'auth_extra',                                         type   => 'scalar', },
		# hide passwords when possible
		{ opts    => ['auth-hide-password', 'ahp'],                        suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'auth_hidepw',                                        type   => 'scalar', },
		# translate base64 strings
		{ opts    => ['auth-plaintext', 'apt'],                            suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'auth_showpt',                                        type   => 'scalar', },
		# auth optional (ignore failure)
		{ opts    => ['auth-optional', 'ao'],                              suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'auth_optional',                                      type   => 'scalar', },
		# req auth if avail
		{ opts    => ['auth-optional-strict', 'aos'],                      suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'auth_optional_strict',                               type   => 'scalar', },
		# report capabilties
		{ opts    => ['support'],                                          suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'get_support',                                        type   => 'scalar', },
		# local interface to use
		{ opts    => ['local-interface', 'li'],                            suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Interface: ',                                        match  => '^.*$',
		  okey    => 'lint',                                               type   => 'scalar', },
		# local port
		{ opts    => ['local-port', 'lport', 'lp'],                        suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Local Port: ',                                       match  => '^\w+$',
		  okey    => 'lport',                                              type   => 'scalar', },
		# use TLS
		{ opts    => ['tls'],                                              suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'tls',                                                type   => 'scalar', },
		# use tls if available
		{ opts    => ['tls-optional', 'tlso'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'tls_optional',                                       type   => 'scalar', },
		# req tls if avail
		{ opts    => ['tls-optional-strict', 'tlsos'],                     suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'tls_optional_strict',                                type   => 'scalar', },
		# use tls if available
		{ opts    => ['tls-on-connect', 'tlsc'],                           suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'tls_on_connect',                                     type   => 'scalar', },
		# local cert to present to server
		{ opts    => ['tls-cert'],                                         suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'tls_cert',                                           type   => 'scalar', },
		# local key to present to server
		{ opts    => ['tls-key'],                                          suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'tls_key',                                            type   => 'scalar', },
		# tls protocol to use
		{ opts    => ['tls-protocol', 'tlsp'],                             suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'tls_protocol',                                       type   => 'scalar', },
		# tls cipher to use
		{ opts    => ['tls-cipher'],                                       suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'tls_cipher',                                         type   => 'scalar', },
		# save tls peer certificate
		{ opts    => ['tls-get-peer-cert'],                                suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'tls_get_peer_cert',                                  type   => 'scalar', },
		# hostname to request in TLS SNI header
		{ opts    => ['tls-sni'],                                          suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'tls_sni_hostname',                                   type   => 'scalar', },
		# require verification of server certificate
		{ opts    => ['tls-verify'],                                       suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'tls_verify',                                         type   => 'scalar', },
		# local key to present to server
		{ opts    => ['tls-ca-path'],                                      suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'tls_ca_path',                                        type   => 'scalar', },
		# suppress output to varying degrees
		{ opts    => ['silent', 'S'],                                      suffix => ':i',
		  cfgs    => OP_ARG_OPT,
		  callout => \&process_opt_silent,
		  okey    => 'silent',                                             type   => 'scalar', },
		# Don't strip From_ line from DATA
		{ opts    => ['no-strip-from', 'nsf'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'no_strip_from',                                      type   => 'scalar', },
		# Don't show send/receive hints (legacy)
		{ opts    => ['no-hints', 'nth'],                                  suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'no_hints',                                           type   => 'scalar', },
		# Don't show transaction hints
		{ opts    => ['no-send-hints', 'nsh'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'no_hints_send',                                      type   => 'scalar', },
		# Don't show transaction hints
		{ opts    => ['no-receive-hints', 'nrh'],                          suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'no_hints_recv',                                      type   => 'scalar', },
		# Don't show transaction hints
		{ opts    => ['no-info-hints', 'nih'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'no_hints_info',                                      type   => 'scalar', },
		# Don't show reception lines
		{ opts    => ['hide-receive', 'hr'],                               suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'hide_receive',                                       type   => 'scalar', },
		# Don't show sending lines
		{ opts    => ['hide-send', 'hs'],                                  suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'hide_send',                                          type   => 'scalar', },
		# Don't echo input on potentially sensitive prompts
		{ opts    => ['protect-prompt', 'pp'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'protect_prompt',                                     type   => 'scalar', },
		# Don't show any swaks-generated, non-error informational lines
		{ opts    => ['hide-informational', 'hi'],                         suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'hide_informational',                                 type   => 'scalar', },
		# Don't send any output to the terminal
		{ opts    => ['hide-all', 'ha'],                                   suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'hide_all',                                           type   => 'scalar', },
		# print lapse for send/recv
		{ opts    => ['show-time-lapse', 'stl'],                           suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'show_time_lapse',                                    type   => 'scalar', },
		# print version and exit
		{ opts    => ['version'],                                          suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'version',                                            type   => 'scalar', },
		# print help and exit
		{ opts    => ['help'],                                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'help',                                               type   => 'scalar', },
		# don't touch the data
		{ opts    => ['no-data-fixup', 'ndf'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'no_data_fixup',                                      type   => 'scalar', },
		# show dumps of the raw read/written text
		{ opts    => ['show-raw-text', 'raw'],                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'show_raw_text',                                      type   => 'scalar', },
		# specify file to write to
		{ opts    => ['output', 'output-file'],                            suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'output_file',                                        type   => 'scalar', },
		# specify file to write to
		{ opts    => ['output-file-stdout'],                               suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'output_file_stdout',                                 type   => 'scalar', },
		# specify file to write to
		{ opts    => ['output-file-stderr'],                               suffix => '=s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'output_file_stderr',                                 type   => 'scalar', },
		# command to communicate with
		{ opts    => ['pipe'],                                             suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Pipe: ',                                             match  => '^.+$',
		  okey    => 'pipe_cmd',                                           type   => 'scalar', },
		# unix domain socket to talk to
		{ opts    => ['socket'],                                           suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'Socket File: ',                                      match  => '^.+$',
		  okey    => 'socket',                                             type   => 'scalar', },
		# the content of the body of the DATA
		{ opts    => ['body'],                                             suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT|OP_FROM_FILE,
		  prompt  => 'Body: ',                                             match  => '.+',
		  okey    => 'body_822',                                           type   => 'scalar', },
		# A file to attach
		{ opts    => ['attach-name'],                                      suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'attach_name',       akey => 'attach_accum',          type   => 'list', },
		# A file to attach
		{ opts    => ['attach-type'],                                      suffix => ':s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'attach_type',       akey => 'attach_accum',          type   => 'list', },
		# A file to attach
		{ opts    => ['attach'],                                           suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_FILE,
		  okey    => 'attach_attach',     akey => 'attach_accum',          type   => 'list', },
		# A file to attach
		{ opts    => ['attach-body'],                                      suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_FILE,
		  okey    => 'attach_body',       akey => 'attach_accum',          type   => 'list', },
		# replacement for %NEW_HEADERS% DATA token
		{ opts    => ['add-header', 'ah'],                                 suffix => ':s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'add_header',                                         type   => 'list', },
		# replace header if exist, else add
		{ opts    => ['header'],                                           suffix => ':s',
		  cfgs    => OP_ARG_REQ,
		  okey    => 'header',                                             type   => 'list', },
		# build options and dump
		{ opts    => ['dump'],                                             suffix => ':s',
		  cfgs    => OP_ARG_OPT,
		  okey    => 'dump_args',                                          type   => 'scalar', },
		# build options and dump the generate message body (EML)
		{ opts    => ['dump-mail'],                                        suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'dump_mail',                                          type   => 'scalar', },
		# attempt PIPELINING
		{ opts    => ['pipeline'],                                         suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'pipeline',                                           type   => 'scalar', },
		# attempt PRDR
		{ opts    => ['prdr'],                                             suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'prdr',                                               type   => 'scalar', },
		# use getpwuid building -f
		{ opts    => ['force-getpwuid'],                                   suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'force_getpwuid',                                     type   => 'scalar', },

		# XCLIENT
		# These xclient_attrs options all get pushed onto an array so that we can determine their order later
		# argument is a raw XCLIENT string
		{ opts    => ['xclient'],                                          suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT string: ',                                   match  => '^.+$',
		  okey    => 'xclient_raw',             akey => 'xclient_accum',   type   => 'list',    },
		# XCLIENT NAME
		{ opts    => ['xclient-name'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT name: ',                                     match  => '^.+$',
		  okey    => 'xclient_name',            akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT ADDR
		{ opts    => ['xclient-addr'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT addr: ',                                     match  => '^.+$',
		  okey    => 'xclient_addr',            akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT PORT
		{ opts    => ['xclient-port'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT port: ',                                     match  => '^.+$',
		  okey    => 'xclient_port',            akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT PROTO
		{ opts    => ['xclient-proto'],                                    suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT proto: ',                                    match  => '^.+$',
		  okey    => 'xclient_proto',           akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT DESTADDR
		{ opts    => ['xclient-destaddr'],                                 suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT destaddr: ',                                 match  => '^.+$',
		  okey    => 'xclient_destaddr',        akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT DESTPORT
		{ opts    => ['xclient-destport'],                                 suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT destport: ',                                 match  => '^.+$',
		  okey    => 'xclient_destport',        akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT HELO
		{ opts    => ['xclient-helo'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT helo: ',                                     match  => '^.+$',
		  okey    => 'xclient_helo',            akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT LOGIN
		{ opts    => ['xclient-login'],                                    suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT login: ',                                    match  => '^.+$',
		  okey    => 'xclient_login',           akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT REVERSE_NAME
		{ opts    => ['xclient-reverse-name'],                             suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'XCLIENT reverse_name: ',                             match  => '^.+$',
		  okey    => 'xclient_reverse_name',    akey => 'xclient_accum',   type   => 'scalar',    },
		# XCLIENT delimiter.  Used to indicate that user wants to start a new xclient attr grouping
		{ opts    => ['xclient-delim'],                                    suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'xclient_delim',           akey => 'xclient_accum',   type   => 'list',    },
		# if set, XCLIENT will proceed even if XCLIENT not advertised
		{ opts    => ['xclient-optional'],                                 suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'xclient_optional',                                   type   => 'scalar', },
		# proceed if xclient not offered, but fail if offered and not accepted
		{ opts    => ['xclient-optional-strict'],                          suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'xclient_optional_strict',                            type   => 'scalar', },
		# we send xclient after starttls by default.  if --xclient-before-starttls will send before tls
		{ opts    => ['xclient-before-starttls'],                          suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'xclient_before_starttls',                            type   => 'scalar', },
		# Don't require that the --xclient-ATTR attributes be advertised by server
		{ opts    => ['xclient-no-verify'],                                suffix => '',
		  cfgs    => OP_ARG_NONE,
		  okey    => 'xclient_no_verify',                                  type   => 'scalar', },
		## xclient send by default after first helo, but can be sent almost anywhere (cf quit-after)
		# { opts    => ['xclient-after'],                                    suffix => ':s',
		#   okey    => 'xclient_after',                                      type   => 'scalar', },

		# PROXY
		# argument is the raw PROXY string
		{ opts    => ['proxy'],                                            suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY string: ',                                     match  => '^.+$',
		  okey    => 'proxy_raw',                                          type   => 'scalar', },
		# PROXY version (1 or 2)
		{ opts    => ['proxy-version'],                                    suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY version: ',                                    match  => '^[12]$',
		  okey    => 'proxy_version',                                      type   => 'scalar', },
		# PROXY protocol family (TCP4 or TCP6)
		{ opts    => ['proxy-family'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY family: ',                                     match  => '^.+$',
		  okey    => 'proxy_family',                                       type   => 'scalar', },
		# PROXY protocol command (LOCAL or PROXY)
		{ opts    => ['proxy-command'],                                    suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY command: ',                                    match  => '^.+$',
		  okey    => 'proxy_command',                                      type   => 'scalar', },
		# PROXY transport protocol
		{ opts    => ['proxy-protocol'],                                   suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY protocol: ',                                   match  => '^.+$',
		  okey    => 'proxy_protocol',                                     type   => 'scalar', },
		# PROXY source address (IPv4 or IPv6)
		{ opts    => ['proxy-source'],                                     suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY source: ',                                     match  => '^.+$',
		  okey    => 'proxy_source',                                       type   => 'scalar', },
		# PROXY source port
		{ opts    => ['proxy-source-port'],                                suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY source_port: ',                                match  => '^.+$',
		  okey    => 'proxy_source_port',                                  type   => 'scalar', },
		# PROXY destination address (IPv4 or IPv6)
		{ opts    => ['proxy-dest'],                                       suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY dest: ',                                       match  => '^.+$',
		  okey    => 'proxy_dest',                                         type   => 'scalar', },
		# PROXY destination port
		{ opts    => ['proxy-dest-port'],                                  suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_FROM_PROMPT,
		  prompt  => 'PROXY dest_port: ',                                  match  => '^.+$',
		  okey    => 'proxy_dest_port',                                    type   => 'scalar', },

		# this option serve no purpose other than testing the deprecation system
		{ opts    => ['trigger-deprecation'],                              suffix => ':s',
		  cfgs    => OP_ARG_REQ|OP_DEPRECATED,
		  okey    => 'trigger_deprecation',                                type   => 'scalar', },
	);

	return(\@G::raw_option_data);
}

# returns %O, the large raw option hash
# This sub is a jumping point.  We will construct an argv based on the different ways that options can be specified
# and call GetOptions multiple times.  We are essentially "layering" options.  First we load from a config file (if
# exists/specified), then from any environment variables, then the actual command line.
sub load_args {
	my %ARGS      = (); # this is the structure that gets returned
	my @fakeARGV  = ();

	# we load our options processing hash here.  We abstract it back from the
	# native getopt-format because we need to be able to intercept "no-" options
	my $option_list = get_option_struct();

	# do a loop through the options and make sure they are structured the way we expect
	foreach my $e (@$option_list) {
		if (!exists($e->{okey}) || !$e->{okey}) {
			ptrans(12, 'Option configuration missing an okey (this is a swaks bug)');
			exit(1);
		}
		elsif (!exists($e->{opts}) || ref($e->{opts}) ne 'ARRAY') {
			ptrans(12, 'Option ' . $e->{okey} . ' missing or corrupt opts key (this is a swaks bug)');
			exit(1);
		}
		elsif (!exists($e->{suffix})) {
			ptrans(12, 'Option ' . $e->{okey} . ' missing suffix key (this is a swaks bug)');
			exit(1);
		}
		elsif (!exists($e->{type}) || $e->{type} !~ /^(scalar|list)$/) {
			ptrans(12, 'Option ' . $e->{okey} . ' missing or invalid type key (this is a swaks bug)');
			exit(1);
		}
		elsif (!exists($e->{cfgs})) {
			ptrans(12, 'Option ' . $e->{okey} . ' missing cfgs key (this is a swaks bug)');
			exit(1);
		}

		$e->{akey} = $e->{okey} if (!exists($e->{akey}));

		# 'cfgs' stores the okey config for easier access later
		$ARGS{cfgs}{$e->{okey}} = $e;
	}

	# we want to process config files first.  There's a default config file in
	# ~/.swaksrc, but it is possible for the user to override this with the
	# --config options.  So, find the one and only file we will use here.
	# If we encounter --config in later processing it is a noop.
	# first find the default file
	my $config_file       = '';
	my $skip_config       = 0;
	my $config_is_default = 1;
	foreach my $v (qw(SWAKS_HOME HOME LOGDIR)) {
		if (exists($ENV{$v}) && length($ENV{$v}) && -f $ENV{$v} . '/.swaksrc') {
			$config_file = $ENV{$v} . '/.swaksrc';
			last;
		}
	}
	# then look through the ENV args to see if another file set there
	if (exists($ENV{SWAKS_OPT_config})) {
		if (!$ENV{SWAKS_OPT_config}) {
			# if exist but not set, it just means "don't use default file"
			$skip_config = 1;
		} else {
			$config_file = $ENV{SWAKS_OPT_config};
			$config_is_default = 0;
		}
	}
	# lastly go (backwards) through original command line looking for config file,
	# choosing the first one found (meaning last one specified)
	for (my $i = scalar(@ARGV) - 1; $i >= 0; $i--) {
		if ($ARGV[$i] =~ /^-?-config$/) {
			if ($i == scalar(@ARGV) - 1 || $ARGV[$i+1] =~ /^-/) {
				$skip_config = 1;
			} else {
				$config_file       = $ARGV[$i+1];
				$config_is_default = 0;
				$skip_config       = 0;
			}
			last;
		}
	}

	# All of the above will result in $config_file either being empty or
	# containing the one and only config file we will use (though merged with DATA)
	if (!$skip_config) {
		my @configs = ('&DATA');
		push(@configs, $config_file) if ($config_file);
		foreach my $configf (@configs) {
			my @fakeARGV = ();
			if (open(C, '<' . $configf)) {
				# "#" in col 0 is a comment
				while (defined(my $m = <C>)) {
					next if ($m =~ m|^#|);
					chomp($m);
					$m = '--' . $m if ($m !~ /^-/);
					push(@fakeARGV, split(/\s/, $m, 2));
				}
				close(C);
			} elsif (!$config_is_default && $configf eq $config_file) {
				# we only print an error if the config was specified explicitly
				ptrans(12, 'Config file ' . $configf . ' could not be opened ($!).  Exiting');
				exit(1);
			}

			# OK, all that work to load @fakeARGV with values from the config file.  Now
			# we just need to process it.  (don't call if nothing set in @fakeARGV)
			fetch_args(\%ARGS, $option_list, \@fakeARGV) if (scalar(@fakeARGV));
			check_opt_processing(\@fakeARGV, 'Config file ' . $configf);
		}
	}

	# OK, %ARGS contains all the settings from the config file.  Now do it again
	# with SWAKS_OPT_* environment variables
	@fakeARGV = ();
	foreach my $v (sort keys %ENV) {
		if ($v =~ m|^SWAKS_OPT_(.*)$|) {
			my $tv = $1; $tv =~ s|_|-|g;
			push(@fakeARGV, '--' . $tv);
			push(@fakeARGV, $ENV{$v}) if (length($ENV{$v}));
		}
	}
	fetch_args(\%ARGS, $option_list, \@fakeARGV) if (scalar(@fakeARGV));
	check_opt_processing(\@fakeARGV, 'environment');

	# and now, after all of that, process the actual cmdline args
	fetch_args(\%ARGS, $option_list, \@ARGV) if (scalar(@ARGV));
	check_opt_processing(\@ARGV, 'command line');

	return(\%ARGS);
}

# if there's anything left in the fake argv after Getopts processed it, it's an error.  There's nothing
# that can be passed in to swaks that isn't an option or an argument to an option, all of which Getopt
# should consume.  So if there's anything left, the user did something weird.  Just let them know and
# error instead of letting them think their ignored stuff is working.
sub check_opt_processing {
	my $argv_local  = shift;
	my $option_type = shift;

	if (scalar(@$argv_local)) {
		ptrans(12, 'Data left in option list when processing  ' . $option_type . ' (' .
		           join(', ', map { "'$_'" } (@$argv_local)) .
		           ').  Exiting');
		exit(1);
	}
}

sub fetch_args {
	my $r          = shift;
	my $l          = shift;
	my $argv_local = shift;

	my %to_delete = ();

	# need to rewrite header-HEADER opts before std option parsing
	# also see if there are any --no- options that need to be processed
	RUNOPTS:
	for (my $i = 0; $i < scalar(@$argv_local); $i++) {
		# before doing any option processing, massage from the optional '--option=arg' format into '--option arg' format.
		if ($argv_local->[$i] =~ /^(-[^=]+)=(.*)$/) {
			$argv_local->[$i] = $1;
			splice(@$argv_local, $i+1, 0, $2);
		}

		# -g is not really necessary.  It is now deprecated. During the deprecation window, make
		# it a straight-up alias to `--data -`.  If has already appeared, just ignore -g.  If
		# --data has not appeared, change -g into `--data -`.
		if ($argv_local->[$i] =~ /^-?-g$/) {
			deprecate('The -g option is deprecated and will be removed. Please use \'--data -\' instead.');
			if (scalar(grep(/^-?-data$/, @$argv_local)) || check_arg('mail_data', $r)) {
				# if --data appears in the current stream or has already appeared in a previous stream, ignore -g
				splice(@$argv_local, $i, 1); # remove the current index from @$argv_local
				redo(RUNOPTS);        # since there's now a new value at $i, redo this iteration of the loop
			}
			else {
				# if we haven't seen --data yet, change -g into `--data -`
				splice(@$argv_local, $i, 1, '--data', '-');
			}
		}

		if ($argv_local->[$i] =~ /^-?-h(?:eader)?-([^:]+):?$/) {
			# rewrite '--header-Foo bar' into '--header "Foo: bar"'
			$argv_local->[$i]   = "--header";
			$argv_local->[$i+1] = $1 . ': ' . $argv_local->[$i+1];
		}
		elsif ($argv_local->[$i] =~ /^-?-no-h(?:eader)?-/) {
			# rewrite '--no-header-Foo' into '--no-header'
			$argv_local->[$i]   = "--no-header";
		}
	}

	# build the actual hash we will pass to GetOptions from our config list ($l):
	# In the end I decided to build this at each call of this sub so that $r
	# is defined.  It's not much of a performance issue.
	my %options = ();
	foreach my $e (@$l) {
		my $k      = join('|', @{$e->{opts}}) . $e->{suffix};
		my $nk     = join('|', map { "no-$_" } (@{$e->{opts}}));
		my $eval;
		if ($e->{type} eq 'scalar' || $e->{type} eq 'list') {
			$eval = "\$options{\$k} = sub { store_option(\$e, \$r, 0, \@_); };"
			      . "\$options{\$nk} = sub { store_option(\$e, \$r, 1, \@_); };";
		}
		else {
			ptrans(12, "Unknown option type '$e->{type}' (this is a swaks bug)");
			exit(1);
		}
		eval($eval);
		if ($@) {
			chomp($@);
			ptrans(12, "Unable to load callback for $k option processing: $@");
			exit(1);
		}
	}

	if (!load("Getopt::Long")) {
		ptrans(12, "Unable to load Getopt::Long for option processing, Exiting");
		exit(1);
	}

	Getopt::Long::Configure("no_ignore_case");
	Getopt::Long::GetOptionsFromArray($argv_local, %options) || exit(1);
}

sub store_option {
	my $cfg_struct = shift;               # this is the option definition structure
	my $opt_struct = shift;               # this is where we will be saving the option for later retrieval
	my $remove     = shift;               # if true, we received a "no-" version of the option, remove all previous instances
	my $opt_name   = shift;               # --xclient-name   || --dump-mail  || -f
	my $opt_value  = shift;               # NAME             || undef        || foo@example.com
	my $accum_key  = $cfg_struct->{akey}; # xclient_attrs    || dump_mail    || mail_from
	my $opt_key    = $cfg_struct->{okey}; # xclient_name     || dump_mail    || mail_from
	my $type       = $cfg_struct->{type}; # scalar or list

	# print "store_options called -> $cfg_struct, $opt_struct, $opt_name, $opt_value, $accum_key, $opt_key, $type\n";

	if ($cfg_struct->{cfgs} & OP_DEPRECATED) {
		deprecate("Option --$opt_name will be removed in the future.  Please see documentation for more information.");
	}

	# 'accum' stores lists of the order they were received in
	$opt_struct->{accums}{$accum_key} ||= [];
	# 'values' stores the actual values and the name of the option that was used to pass it
	$opt_struct->{values}{$opt_key}   ||= [];

	# if we're recording a scalar or were asked to remove, reset the values list to throw away any previous values
	# and remove any previous recordings of this okey from the accumulator list
	if ($type eq 'scalar' || $remove) {
		$opt_struct->{values}{$opt_key}   = [];
		$opt_struct->{accums}{$accum_key} = [ grep { $_ ne $opt_key } (@{$opt_struct->{accums}{$accum_key}}) ];
	}

	# if we were asked to remove (which means called with a "--no-" prefix), get out now, there's nothing to record
	return if ($remove);

	push(@{$opt_struct->{accums}{$accum_key}}, $opt_key);

	my $arg = $opt_value;
	if ($cfg_struct->{callout}) {
		$arg = $cfg_struct->{callout}("$opt_name", $arg);
	}

	push(@{$opt_struct->{values}{$opt_key}}, {
		okey => $opt_key,
		akey => $accum_key,
		opt  => "$opt_name",
		arg  => $arg,
	});
}

# take a string and quote it such that it could be used in the shell
# O'Reilley -> 'O'\''Reilley'
sub shquote { my $s = shift; $s =~ s%'%'\\''%g; return "'$s'"; }

sub reconstruct_options {
	my $o            = shift; # ref to raw option hash (as returned by load_args)
	my @c            = ();    # array to hold our reconstructed command line
	my %already_seen = ();    # for okeys like xclient_attrs, they only need to be processed once
	my %indexer      = ();

	foreach my $opt (@G::raw_option_data) {
		next if ($already_seen{$opt->{akey}});
		next if (!exists($o->{accums}{$opt->{akey}}));

		foreach my $okey (@{$o->{accums}{$opt->{akey}}}) {
			$indexer{$okey} ||= 0;
			my $optStruct     = $o->{values}{$okey}[$indexer{$okey}];
			my $lopt          = $o->{cfgs}{$okey}{opts}[0];

			push(@c, '--'.$lopt);
			if (length($optStruct->{arg}) && !($o->{cfgs}{$okey}{cfgs} & OP_ARG_NONE)) {
				if ($okey eq 'auth_pass') {
					push(@c, shquote('%RAW_PASSWORD_STRING%'));
				}
				else {
					push(@c, shquote($optStruct->{arg}));
				}
			}
		}
		$already_seen{$opt->{akey}} = 1;
	}

	#print join(', ', @c), "\n";
	return join(' ', @c);
}

sub get_accum {
	my $accum_key = shift;
	my $userOpts  = shift;

	if (!exists($userOpts->{accums}{$accum_key})) {
		return([]);
	}

	return($userOpts->{accums}{$accum_key});
}

# I might change this interface later, but I want a way to check whether the user provided the option
# without actually processing it.
sub check_arg {
	my $opt      = shift;
	my $userOpts = shift;

	if (exists($userOpts->{values}{$opt}) && scalar(@{$userOpts->{values}{$opt}})) {
		return(1);
	}

	return(0);
}

# get the next value for $opt without doing any processing or popping it off of the list.
sub peek_arg {
	my $opt       = shift; # this should correspond to an okey from the @G::raw_option_data array
	my $userOpts  = shift; # all options we got from the command line

	if (!exists($userOpts->{values}{$opt})) {
		return(undef());
	}

	if (!scalar(@{$userOpts->{values}{$opt}})) {
		return(undef());
	}

	return($userOpts->{values}{$opt}[0]{arg});
}

# there was a ton of repeated, boiler plate code in process_args.  Attempt to abstract it out to get_arg
sub get_arg {
	my $opt       = shift; # this should correspond to an okey from the @G::raw_option_data array
	my $userOpts  = shift; # all options we got from the command line
	my $optConfig = shift;
	my $force     = shift;
	my $arg;
	my $argExt;
	my $return;

	# print "in get_arg, opt = $opt\n";

	# If the user didn't pass in a specific option config, look it up from the global option config
	if (!$optConfig) {
		if (!exists($userOpts->{cfgs}{$opt})) {
			ptrans(12, "Internal option processing error: asked to evaluate non-existent option $opt");
			exit(1);
		}
		$optConfig = $userOpts->{cfgs}{$opt};
	}

	# $arg will be the value actually provided on the command line
	# !defined = not provided
	# defined && !length = option provided but no argument provided
	# defined && length = option provided and argument provided
	if (!exists($userOpts->{values}{$opt})) {
		# if the caller passed in $force, we act as if the option is present with an empty arg
		# this is used when we need to use get_arg features like interact() even when the user
		# didn't specify the option (specifically, --auth forces --auth-password to need to be
		# processed, even if the user didn't pass it in)
		$arg = $force ? '' : undef();
	}
	else {
		$argExt = shift(@{$userOpts->{values}{$opt}});
		$arg    = $argExt->{arg};
	}

	# this option takes no arguments - it's a straight boolean
	if ($optConfig->{cfgs} & OP_ARG_NONE) {
		if ($arg) {
			$return = 1;
		}
		else {
			$return = 0;
		}
	}

	# if the option is present, it must have an argument.
	# theoretically I should have code here actually requiring the argument,
	# but at the moment that's being handled by Getopt::Long
	elsif ($optConfig->{cfgs} & OP_ARG_REQ) {
		if (!defined($arg)) {
			# the opt wasn't specified at all.  Perfectly legal, return undef
			$return = undef;
		}
		else {
			# if there was an arg provided, just return it
			if (length($arg)) {
				$return = $arg;
			}
			# No arg, but we were requested to prompt the user - do so
			elsif ($optConfig->{cfgs} & OP_FROM_PROMPT) {
				if (!exists($optConfig->{prompt})) {
					ptrans(12, "Internal option processing error: option $argExt->{opt} missing required prompt key (this is a swaks bug)");
					exit(1);
				}
				if (!exists($optConfig->{match})) {
					ptrans(12, "Internal option processing error: option $argExt->{opt} missing required match key (this is a swaks bug)");
					exit(1);
				}
				$return = interact($optConfig->{prompt}, $optConfig->{match}, $optConfig->{cfgs} & OP_SENSITIVE);
			}
			# No arg, no request to prompt - this is an error since we're requiring an arg
			else {
				ptrans(12, "Option processing error: option $argExt->{opt} specified with no argument");
				exit(1);
			}

			# OP_FROM_FILE means that the above options might have resolved into '-' or @filename.  If so, return the actual
			# data contained in STDIN/@filename
			if ($optConfig->{cfgs} & OP_FROM_FILE) {
				if ($return eq '-') {
					if (defined($G::stdin)) {
						# multiple options can specify stdin, but we can only read it once.  If anyone has
						# already read stdin, provide the saved value here
						$return = $G::stdin;
					}
					else {
						$return   = join('', <STDIN>);
						$G::stdin = $return;
					}
				}
				elsif ($return =~ /^\@\@/) {
					# if the argument starts with \@\@, we take that to mean that the user wants a literal value that starts
					# with an @.  The first @ is just an indicator, so strip it off before continuing
					$return =~ s/^\@//;
				}
				elsif ($return =~ /^\@/) {
					# a single @ means it's a filename.  Open it and use the contents as the return value
					$return =~ s/^\@//;
					if (!open(F, "<$return")) {
						ptrans(12, "Option processing error: file $return not openable for option $argExt->{opt} ($!)");
						exit(1);
					}
					$return = join('', <F>);
					close(F);
				}

				{
					# All of the functionality in this bare block is deprecated, remove the whole thing later.
					# if --data and single line, try to open it, error otherwise
					# if !--data and is openable file, try to open and read, otherwise just use it as literal data
					if ($argExt->{opt} eq 'data') {
						# the old rule for --data was that anything that didn't have a newline in it would be treated
						# as a file, and we would error if we couldn't open it. That would prevent us from sending
						# typoed filenames as the data of messages
						if ($return !~ m/\\n|\n|%NEWLINE%/) {
							deprecate('Inferring a filename from the argument to --' . $argExt->{opt} .
							          ' will be removed in the future.  Prefix filenames with \'@\' instead.');
							if (!open(F, "<$return")) {
								ptrans(12, "$argExt->{opt} option appears to be a file but is not openable: $return ($!)");
								exit(1);
							}
							$return = join('', <F>);
							close(F);
						}
					}
					elsif (open(F, "<$return")) {
						# the old rule for any other file option (--attach, --attach-body, --body) was that
						# if it was openable, we would use the contents of the file, otherwise we would
						# use the string itself
						deprecate('Inferring a filename from the argument to --' . $argExt->{opt} .
						          ' will be removed in the future.  Prefix filenames with \'@\' instead.');
						$return = join('', <F>);
						close(F);
					}
				}
			}
		}
	}

	# The option can be present with or without an argument
	# any "true" return value will be an actual provided option
	# false and defined = option given but no argument given
	# false and undefined = option not specified
	elsif ($optConfig->{cfgs} & OP_ARG_OPT) {
		if (!defined($arg)) {
			# the opt wasn't specified at all.  Perfectly legal, return undef
			$return = undef;
		}
		else {
			# we have an opt and an arg, return the arg
			$return = $arg;
		}
	}

	# if we read the last arg off an array, put it back on the array for future reads.  I can't
	# decide if this is the right behavior or not, but this makes it more like scalars, which
	# can (and in a couple of cases, must) be read multiple times.
	if (defined($arg) && ref($userOpts->{values}{$opt}) && !scalar(@{$userOpts->{values}{$opt}})) {
		push(@{$userOpts->{values}{$opt}}, $argExt);
	}

	# print "returning ";
	# if (defined($return)) {
	# 	print length($return) ? "$return\n" : "defined but empty\n";
	# }
	# else {
	# 	print "undefined\n";
	# }
	return($return);
}

# A couple of global options are set in here, they will be in the G:: namespace
sub process_args {
	my $o     = shift; # This is the args we got from command line
	my %n     = ();    # This is the hash we will return w/ the fixed-up args
	my $a     = get_option_struct(); # defining information for all options

	# handle the output file handles early so they can be used for errors
	# we don't need to keep track of the actual files but it will make debugging
	# easier later
	$G::trans_fh_oh        = \*STDOUT;
	$G::trans_fh_of        = "STDOUT";
	$G::trans_fh_eh        = \*STDERR;
	$G::trans_fh_ef        = "STDERR";
	my $output_file        = get_arg('output_file', $o);
	my $output_file_stderr = get_arg('output_file_stderr', $o) || $output_file;
	my $output_file_stdout = get_arg('output_file_stdout', $o) || $output_file;
	if ($output_file_stderr) {
		if (!open(OUTEFH, '>>'.$output_file_stderr)) {
			ptrans(12, 'Unable to open ' . $output_file_stderr . ' for writing');
			exit(1);
		}
		$G::trans_fh_eh = \*OUTEFH;
		$G::trans_fh_ef = $output_file_stderr;
	}
	if ($output_file_stdout && $output_file_stdout eq $output_file_stderr) {
		$G::trans_fh_oh = $G::trans_fh_eh;
		$G::trans_fh_of = $G::trans_fh_ef;
	}
	elsif ($output_file_stdout) {
		if (!open(OUTOFH, '>>'.$output_file_stdout)) {
			ptrans(12, 'Unable to open ' . $output_file_stdout . ' for writing');
			exit(1);
		}
		$G::trans_fh_oh = \*OUTOFH;
		$G::trans_fh_of = $output_file_stdout;
	}

	if (get_arg('no_hints', $o)) {
		$G::no_hints_send = 1;
		$G::no_hints_recv = 1;
	}
	else {
		$G::no_hints_send      = get_arg('no_hints_send', $o);
		$G::no_hints_recv      = get_arg('no_hints_recv', $o);
	}
	$G::dump_mail          = get_arg('dump_mail', $o);
	$G::suppress_data      = get_arg('suppress_data', $o);
	$G::no_hints_info      = get_arg('no_hints_info', $o);
	$G::hide_send          = get_arg('hide_send', $o);
	$G::hide_receive       = get_arg('hide_receive', $o);
	$G::hide_informational = get_arg('hide_informational', $o);
	$G::hide_all           = get_arg('hide_all', $o);
	$G::show_raw_text      = get_arg('show_raw_text', $o);
	$G::protect_prompt     = get_arg('protect_prompt', $o);
	$G::pipeline           = get_arg('pipeline', $o);
	$G::prdr               = get_arg('prdr', $o);
	$G::silent             = get_arg('silent', $o) || 0;

	if (defined(my $dump_args = get_arg('dump_args', $o))) {
		map { $G::dump_args{uc($_)} = 1; } (split('\s*,\s*', $dump_args)); # map comma-delim options into a hash
		$G::dump_args{'ALL'} = 1 if (!scalar(keys(%G::dump_args)));        # if no options were given, just set ALL
	}

	my $mail_server_t = get_arg('mail_server', $o);
	my $socket_t      = get_arg('socket', $o);
	my $pipe_cmd_t    = get_arg('pipe_cmd', $o);

	# it is an error if >1 of --server, --socket, or --pipe is specified
	if ((defined($mail_server_t) && defined($socket_t))   ||
	    (defined($mail_server_t) && defined($pipe_cmd_t)) ||
	    (defined($pipe_cmd_t)    && defined($socket_t)))
	{
		ptrans(12, "Multiple transport types specified, exiting");
		exit(1);
	}

	my %protos = (
		smtp    => { proto => 'smtp',  auth => 0, tls => '0' },
		ssmtp   => { proto => 'esmtp', auth => 0, tls => 'c' },
		ssmtpa  => { proto => 'esmtp', auth => 1, tls => 'c' },
		smtps   => { proto => 'smtp',  auth => 0, tls => 'c' },
		esmtp   => { proto => 'esmtp', auth => 0, tls => '0' },
		esmtpa  => { proto => 'esmtp', auth => 1, tls => '0' },
		esmtps  => { proto => 'esmtp', auth => 0, tls => 's' },
		esmtpsa => { proto => 'esmtp', auth => 1, tls => 's' },
		lmtp    => { proto => 'lmtp',  auth => 0, tls => '0' },
		lmtpa   => { proto => 'lmtp',  auth => 1, tls => '0' },
		lmtps   => { proto => 'lmtp',  auth => 0, tls => 's' },
		lmtpsa  => { proto => 'lmtp',  auth => 1, tls => 's' },
	);
	$G::protocol            = lc(get_arg('mail_protocol', $o)) || 'esmtp';
	my $tls                 = get_arg('tls', $o);
	my $tls_optional        = get_arg('tls_optional', $o);
	my $tls_optional_strict = get_arg('tls_optional_strict', $o);
	my $tls_on_connect      = get_arg('tls_on_connect', $o);
	if (!$protos{$G::protocol}) {
		ptrans(12, "Unknown protocol $G::protocol specified, exiting");
		exit(1);
	}
	my $auth_user_t            = get_arg('auth_user', $o);
	my $auth_pass_t            = get_arg('auth_pass', $o);
	my $auth_optional_t        = get_arg('auth_optional', $o);
	my $auth_optional_strict_t = get_arg('auth_optional_strict', $o);
	my $auth_t                 = get_arg('auth', $o);
	if ($protos{$G::protocol}{auth} && !$auth_user_t && !$auth_pass_t && !$auth_optional_t && !$auth_optional_strict_t && !$auth_t) {
		$auth_t = ''; # cause auth to be processed below
	}
	if ($protos{$G::protocol}{tls} && !$tls && !$tls_optional && !$tls_optional_strict && !$tls_on_connect){
		# 'touch' the variable so we process it below
		if ($protos{$G::protocol}{tls} eq 's') {
			$tls = 1;
		} elsif ($protos{$G::protocol}{tls} eq 'c') {
			$tls_on_connect = 1;
		}
	}
	$G::protocol = $protos{$G::protocol}{proto};

	# set global options for --quit-after, --drop-after, and --drop-after-send
	foreach my $opt ('quit_after', 'drop_after', 'drop_after_send') {
		no strict "refs";
		if (my $value = get_arg($opt, $o)) {
			${"G::$opt"} = lc($value);
			if (${"G::$opt"} =~ /^[el]hlo$/)        { ${"G::$opt"} = 'helo';       }
			elsif (${"G::$opt"} =~ /first-[el]hlo/) { ${"G::$opt"} = 'first-helo'; }
			elsif (${"G::$opt"} eq 'starttls')      { ${"G::$opt"} = 'tls';        }
			elsif (${"G::$opt"} eq 'banner')        { ${"G::$opt"} = 'connect';    }
			elsif (${"G::$opt"} eq 'from')          { ${"G::$opt"} = 'mail';       }
			elsif (${"G::$opt"} eq 'to')            { ${"G::$opt"} = 'rcpt';       }
			elsif (${"G::$opt"} ne 'connect' && ${"G::$opt"} ne 'first-helo' &&
			       ${"G::$opt"} ne 'tls'     && ${"G::$opt"} ne 'helo'       &&
			       ${"G::$opt"} ne 'auth'    && ${"G::$opt"} ne 'mail'       &&
			       ${"G::$opt"} ne 'rcpt'    && ${"G::$opt"} ne 'xclient'    &&
			       ${"G::$opt"} ne 'data'    && ${"G::$opt"} ne 'dot')
			{
				ptrans(12, "Unknown $opt value " . ${"G::$opt"} . ", exiting");
				exit(1);
			}
			# only rcpt, data, and dot _require_ a to address
			$G::server_only = 1 if (${"G::$opt"} !~ /^(rcpt|data|dot)$/);

			# data and dot aren't legal for quit_after
			if ($opt eq 'quit_after' && (${"G::$opt"} eq 'data' || ${"G::$opt"} eq 'dot')) {
				ptrans(12, "Unknown $opt value " . ${"G::$opt"} . ", exiting");
				exit(1);
			}
		} else {
			${"G::$opt"} = '';
		}
	}

	# set global flag for -stl flag
	$G::show_time_lapse = get_arg('show_time_lapse', $o);
	if (defined($G::show_time_lapse)) {
		if (length($G::show_time_lapse) && $G::show_time_lapse !~ /^i/i) {
			ptrans(12, "Unknown argument '$G::show_time_lapse' to option show-time-lapse, exiting");
			exit(1);
		}
		if (avail("hires_timing") && $G::show_time_lapse !~ /^i/i) {
			$G::show_time_lapse = 'hires';
		}
		else {
			$G::show_time_lapse = 'integer';
		}
	}

	# pipe command, if one is specified
	if ($pipe_cmd_t) {
		$G::link{process} = $pipe_cmd_t;
		$G::link{type}    = 'pipe';
	}

	# socket file, if one is specified
	if ($socket_t) {
		$G::link{sockfile} = $socket_t;
		$G::link{type}     = 'socket-unix';
	}

	$n{force_getpwuid} = get_arg('force_getpwuid', $o); # make available for --dump
	my $user           = get_username($n{force_getpwuid});
	my $hostname       = get_hostname();

	# SMTP mail from
	if (!($n{from} = get_arg('mail_from', $o))) {
		if ($hostname || ($G::server_only && $G::quit_after ne 'mail' && $G::drop_after ne 'mail' && $G::drop_after_send ne 'mail')) {
			# if we have a hostname, or it doesn't matter anyway because we won't actually need it, use our manufactured from
			$n{from} = "$user\@$hostname";
		}
		else {
			ptrans(12, "From string required but couldn't be determined automatically.  Please use --from");
			exit(1);
		}
	}
	$n{from} = '' if ($n{from} eq '<>');

	# local interface and port
	($G::link{lint},$G::link{lport}) = parse_server(get_arg('lint', $o), get_arg('lport', $o));
	if ($G::link{lport} && $G::link{lport} !~ /^\d+$/) {
		if (my $port = getservbyname($G::link{lport}, 'tcp')) {
			$G::link{lport} = $port;
		}
		else {
			ptrans(12, "unable to resolve service name $G::link{lport} into a port, exiting");
			exit(1);
		}
	}

	# SMTP helo/ehlo
	if (!($n{helo} = get_arg('mail_helo', $o))) {
		if ($hostname || ($G::quit_after eq 'connect' || $G::drop_after eq 'connect' || $G::drop_after_send eq 'connect')) {
			# if we have a hostname, or it doesn't matter anyway because we won't actually need it, use our manufactured from
			$n{helo} = $hostname;
		}
		else {
			ptrans(12, "Helo string required but couldn't be determined automatically.  Please use --helo");
			exit(1);
		}
	}

	# SMTP server, port and rcpt-to are interdependant, so they are handled together
	$G::link{type}                    ||= 'socket-inet';
	($G::link{server},$G::link{port})   = parse_server($mail_server_t, get_arg('mail_port', $o));
	$n{to}                              = get_arg('mail_to', $o);
	# we absolutely must have a recipient. If we don't have one yet, prompt for one
	if (!$n{to} && !($G::server_only && ($G::link{server} || $G::link{type} eq 'socket-unix' || $G::link{type} eq 'pipe'))) {
		$n{to} = interact("To: ", '^.+$'); # WCSXXXFIXME I wish we could look up the prompt and re from $a
	}

	# try to catch obvious -s/-li/-4/-6 errors as soon as possible.  We don't actually do any DNS
	# lookups ourselves, so errors like -s being a domain with only A RRs and -li being a domain
	# with only AAAA RRs, or -s being an ipv6 and -li being a domain with only A RRs, will
	# get passed into the IO::Socket module to deal with and will just registed as a connection
	# failure.
	if ($G::link{type} eq 'socket-inet') {
		my $forceIPv4 = get_arg('force_ipv4', $o);
		my $forceIPv6 = get_arg('force_ipv6', $o);
		if ($forceIPv4 && $forceIPv6) {
			ptrans(12, "Options -4 and -6 are mutually exclusive, cannot proceed");
			exit 1;
		} elsif ($forceIPv6) {
			$G::link{force_ipv6} = 1;
		} elsif ($forceIPv4) {
			$G::link{force_ipv4} = 1;
		}

		if ($n{copy_routing} = get_arg('copy_routing', $o)) {
			$G::link{server} ||= get_server($n{copy_routing});
		}
		else {
			$G::link{server} ||= get_server($n{to});
		}

		if ($forceIPv4 && $G::link{server} =~ m|:|) {
			ptrans(12, "Option -4 is set but server appears to be ipv6, cannot proceed");
			exit 1;
		} elsif ($forceIPv4 && $G::link{lint} =~ m|:|) {
			ptrans(12, "Option -4 is set but local-interface appears to be ipv6, cannot proceed");
			exit 1;
		} elsif ($forceIPv6 && $G::link{server} =~ m|^\d+\.\d+\.\d+\.\d+$|) {
			ptrans(12, "Option -6 is set but server appears to be ipv4, cannot proceed");
			exit 1;
		} elsif ($forceIPv6 && $G::link{lint} =~ m|^\d+\.\d+\.\d+\.\d+$|) {
			ptrans(12, "Option -6 is set but local-interface appears to be ipv4, cannot proceed");
			exit 1;
		} elsif ($G::link{server} =~ m|:| && $G::link{lint} =~ m|^\d+\.\d+\.\d+\.\d+$|) {
			ptrans(12, "server is ipv6 but local-interface is ipv4, cannot proceed");
			exit 1;
		} elsif ($G::link{server} =~ m|^\d+\.\d+\.\d+\.\d+$| && $G::link{lint} =~ m|:|) {
			ptrans(12, "server is ipv4 but local-interface is ipv6, cannot proceed");
			exit 1;
		}
	}

	# Verify we are able to handle the requested transport
	if ($G::link{type} eq 'pipe') {
		if (!avail("pipe")) {
			ptrans(12, avail_str("pipe").".  Exiting");
			exit(10);
		}
	} else {
		if (!avail("socket")) {
			ptrans(12, avail_str("socket").".  Exiting");
			exit(10);
		} elsif (($G::link{force_ipv6} || $G::link{server} =~ m|:| ||  $G::link{lint} =~ m|:|) && !avail("ipv6")) {
			ptrans(12, avail_str("ipv6").".  Exiting");
			exit(10);
		}
	}

	# SMTP timeout
	$G::link{timeout} = time_to_seconds(get_arg('timeout', $o) // '30s');

	my $dab_sp            = get_arg('dab_sp', $o);
	my $dump_as_body      = get_arg('dump_as_body', $o);
	$dump_as_body         = '' if ($dab_sp && !defined($dump_as_body));
	my $body              = 'This is a test mailing'; # default message body
	$body                 = 'DUMP_AS_BODY_HAS_BEEN_SET' if (defined($dump_as_body));
	my $bound             = '';
	my $main_content_type = 'multipart/mixed';
	my $stdin             = undef;
	if (defined(my $body_822_t = get_arg('body_822', $o))) {
		# the --body option is the entire 822 body and trumps any other options
		# that mess with the body
		$body = $body_822_t;
	}
	my $attach_accum = get_accum('attach_accum', $o);
	if (scalar(@$attach_accum)) {
		# this option is a list of files (or STDIN) to attach.  In this case,
		# the message become a mime message and the "body" goes in the
		# first text/plain part
		my $mime_type = '%SWAKS_DEFAULT_MIMETYTPE%';
		my $next_name = undef();
		my %parts     = ( body => [], rest => [] );
		$bound        = "----=_MIME_BOUNDARY_000_$$";
		foreach my $part (@$attach_accum) {
			if ($part eq 'attach_type') {
				$mime_type = get_arg($part, $o);
			}
			elsif ($part eq 'attach_name') {
				$next_name = get_arg($part, $o);
			}
			elsif ($part eq 'attach_body') {
				if ($mime_type eq '%SWAKS_DEFAULT_MIMETYTPE%') {
					$mime_type = 'text/plain';
				}
				push(@{$parts{body}}, { body => get_arg($part, $o), type => $mime_type });
				$next_name = undef(); # can't set filename for body, unset next_name so random attachment doesn't get it
				$mime_type = '%SWAKS_DEFAULT_MIMETYTPE%'; # after each body, reset the default mime type
			}
			elsif ($part eq 'attach_attach') {
				my $name  = peek_arg($part, $o);
				my $tpart = { body => get_arg($part, $o), type => $mime_type };
				if (defined($next_name)) {
					$tpart->{name} = $next_name;
					$next_name     = undef();
				}
				else {
					my $filename = $name;
					$filename =~ s/^\@//;
					if ($name ne '-' && $filename !~ /^\@/ && $name ne $tpart->{body} && -f $filename) {
						# name will have the unprocessed arg.  If we think it came from a file, use the filename for
						# the attachment name.  Not super happy with this logic, try to improve in the future
						($tpart->{name}) = $name =~ m|/?([^/]+)$|;
					}
				}
				push(@{$parts{rest}}, $tpart);
			} else {
				ptrans(12, "Error processing attach args, unknown type $part when processing attachment options");
				exit(1);
			}
		}

		# if no body parts were set via --attach-body, set a text/plain body to $body
		if (!scalar(@{$parts{body}})) {
			push(@{$parts{body}}, { body => $body, type => 'text/plain' });
		}

		$body = '';
		if (!scalar(@{$parts{rest}})) {
			# if there are no non-body parts
			if (scalar(@{$parts{body}}) > 1) {
				$main_content_type = 'multipart/alternative';
			}
			else {
				$main_content_type = 'multipart/mixed';
			}

			foreach my $part (@{$parts{body}}) {
				$body .= encode_mime_part($part, $bound, 1);
			}
		}
		else {
			# otherwise, there's a mixture of both body and other. multipart/mixed
			$main_content_type = 'multipart/mixed';
			if (scalar(@{$parts{body}}) > 1) {
				# we have multiple body parts, plus other attachments.  Need to create a mp/mixes mime object for the bodies
				my $mp_bound = "----=_MIME_BOUNDARY_004_$$";

				$body .= "--$bound\n"
				      .  'Content-Type: multipart/alternative; boundary="' . $mp_bound . '"' . "\n\n";

				foreach my $part (@{$parts{body}}) {
					$body .= encode_mime_part($part, $mp_bound, 1);
				}
				$body .= "--$mp_bound--\n";
			}
			else {
				$body .= encode_mime_part($parts{body}[0], $bound, 1);
			}

			# now handle the non-body attachments
			foreach my $part (@{$parts{rest}}) {
				$body .= encode_mime_part($part, $bound);
			}
		}
		$body .= "--$bound--\n";
	}
	$body =~ s|%SWAKS_DEFAULT_MIMETYTPE%|application/octet-stream|g;

	# SMTP DATA
	$n{data} = get_arg('mail_data', $o) ||
               'Date: %DATE%\nTo: %TO_ADDRESS%\nFrom: %FROM_ADDRESS%\nSubject: test %DATE%\n' .
	           "Message-Id: <%MESSAGEID%>\n" .
	           "X-Mailer: swaks v%SWAKS_VERSION% jetmore.org/john/code/swaks/".'\n' .
	           ($bound ? 'MIME-Version: 1.0\nContent-Type: ' . $main_content_type . '; boundary="' . $bound. '"\n' : '') .
	           '%NEW_HEADERS%' . # newline will be added in replacement if it exists
	           '\n' .
	           '%BODY%\n';
	if (!get_arg('no_data_fixup', $o)) {
		$n{data}            =~ s/%BODY%/$body/g;
		$n{data}            =~ s/\\n/\r\n/g;
		my $addHeader_accum =  get_accum('add_header', $o);
		my $addHeaderOpt    =  [];

		foreach my $okey (@$addHeader_accum) {
			push(@$addHeaderOpt, get_arg($okey, $o));
		}

		# split the headers off into their own struct temporarily to make it much easier to manipulate them
		my $header;
		my @headers = ();
		my %headers = ();

		# cut the headers off of the data
		if ($n{data} =~ s/\A(.*?)\r?\n\r?\n//s) {
			$header = $1;
		}
		else {
			$header  = $n{data};
			$n{data} = '';
		}

		# build the header string into an object.  Each header is an array, each index is a line (to handle header continuation lines)
		foreach my $headerLine (split(/\r?\n/, $header)) {
			if ($headerLine =~ /^\s/) {
				# continuation line
				if (scalar(@headers)) {
					push(@{$headers[-1]}, $headerLine);
				}
				else {
					# it's illegal to have a continuation line w/o a previous header, but we're a test tool
					push(@headers, [ $headerLine ]);
				}
			}
			elsif ($headerLine =~ /^(\S[^:]+):/) {
				# properly formed header
				push(@headers, [ $headerLine ]);
				$headers{$1} = $headers[-1];
			}
			else {
				# malformed header - no colon.  Allow it anyway, we're a test tool
				push(@headers, [ $headerLine ]);
				$headers{$headerLine} = $headers[-1];
			}
		}

		# If the user specified headers and the header exists, replace it.  If not, push it onto add_header to be added as new
		my $header_accum =  get_accum('header', $o);
		my $headerOpt    =  [];
		foreach my $okey (@$header_accum) {
			push(@$headerOpt, get_arg($okey, $o));
		}
		foreach my $headerLine (map { split(/\\n/) } @{$headerOpt}) {
			if (my($headerName) = $headerLine =~ /^([^:]+):/) {
				if ($headers{$headerName}) {
					$headers{$headerName}[0] = $headerLine;
					splice(@{$headers{$headerName}}, 1); # remove from index 1 onward, if they existed (possible continuations)
				}
				else {
					push(@{$addHeaderOpt}, $headerLine);
				}
			}
			else {
				push(@{$addHeaderOpt}, $headerLine);
			}
		}

		# rebuild the header using our (possibly replaced) headers
		my $newHeader = '';
		foreach my $headerObj (@headers) {
			foreach my $line (@$headerObj) {
				$newHeader .= $line . "\r\n";
			}
		}

		# if there are new headers, add them as appropriate
		if ($newHeader =~ /%NEW_HEADERS%/) {
			$n{add_header} = join("\r\n", @{$addHeaderOpt}) . "\r\n" if (@{$addHeaderOpt});
			$newHeader     =~ s/%NEW_HEADERS%/$n{add_header}/g;
		} elsif (scalar(@{$addHeaderOpt})) {
			foreach my $line (@{$addHeaderOpt}) {
				$newHeader .= $line . "\r\n";
			}
		}

		# Now re-assemble our data by adding the headers back on to the front
		$n{data} = $newHeader . "\r\n" . $n{data};

		$n{data} =~ s/\\n|%NEWLINE%/\r\n/g;
		$n{data} =~ s/%FROM_ADDRESS%/$n{from}/g;
		$n{data} =~ s/%TO_ADDRESS%/$n{to}/g;
		$n{data} =~ s/%MESSAGEID%/get_messageid()/ge;
		$n{data} =~ s/%SWAKS_VERSION%/$p_version/g;
		$n{data} =~ s/%DATE%/get_date_string()/ge;
		$n{data} =~ s/^From [^\n]*\n// if (!get_arg('no_strip_from', $o));
		$n{data} =~ s/\r?\n\.\r?\n?$//s;   # If there was a trailing dot, remove it
		$n{data} =~ s/\n\./\n../g;         # quote any other leading dots
		$n{data} =~ s/([^\r])\n/$1\r\n/gs;
		$n{data} =~ s/([^\r])\n/$1\r\n/gs; # this identical call is not a bug, called twice to get consecutive \n correctly
		$n{data} .= "\r\n.";               # add a trailing dot
	}

	# Handle TLS options
	# tls => 0 - no.  STARTTLS must be advertised and must succeed, else error.
	#        1 - yes.  Success if not advertised, advertised and fails _or_ succeeds.
	#        2 - strict.  Satisfied if not advertised, or advertised and succeeded.
	#                     However, if it's advertised and fails, it's an error.
	$G::tls_optional      = 1 if ($tls_optional);
	$G::tls_optional      = 2 if ($tls_optional_strict);
	$G::tls               = 1 if ($tls || $G::tls_optional);
	$G::tls_on_connect    = 1 if ($tls_on_connect);
	$G::link{tls}{active} = 0;
	if ($G::tls || $G::tls_on_connect) {
		if (!avail("tls")) {
			if ($G::tls_optional) {
				$G::tls = undef; # so we won't try it later
				ptrans(12,avail_str("tls"));
			} else {
				ptrans(12,avail_str("tls").".  Exiting");
				exit(10);
			}
		}
		$G::tls_verify       = get_arg('tls_verify', $o);
		$G::tls_sni_hostname = get_arg('tls_sni_hostname', $o);
		$G::tls_cipher       = get_arg('tls_cipher', $o);
		$G::tls_cert         = get_arg('tls_cert', $o);
		$G::tls_key          = get_arg('tls_key', $o);
		if (($G::tls_cert || $G::tls_key) && !($G::tls_cert && $G::tls_key)) {
			ptrans(12, "--tls-cert and --tls-key require each other.  Exiting");
			exit(1);
		}
		if (($G::tls_ca_path = get_arg('tls_ca_path', $o)) && !-f $G::tls_ca_path && !-d $G::tls_ca_path) {
			ptrans(12, "--tls-ca-path: $G::tls_ca_path is not a valid file or directory.  Exiting.");
			exit(1);
		}

		# this is kind of a kludge.  There doesn't appear to be a specific openssl call to find supported
		# protocols, but the OP_NO_protocol functions exist for supported protocols.  Loop through
		# "known" protocols (which will unfortunately need to be added-to by hand when new protocols
		# become available) to find out which of them are available (when adding new types here, see
		# also the code that calls Net::SSLeay::version() and translates to a readable value
		@G::tls_supported_protocols = ();
		foreach my $p (qw(SSLv2 SSLv3 TLSv1 TLSv1_1 TLSv1_2 TLSv1_3)) {
			eval { no strict "refs"; &{"Net::SSLeay::OP_NO_$p"}(); };
			push(@G::tls_supported_protocols, $p) if (!$@);
		}

		if (my $tls_protocols = get_arg('tls_protocol', $o)) {
			@G::tls_protocols = ();
			my @requested = split(/,\s*/, $tls_protocols);
			if (my $c = scalar(grep(/^no_/i, @requested))) {
				if ($c != scalar(@requested)) {
					ptrans(12, "cannot mix X and no_X forms in --tls-protocol option");
					exit(1);
				}
			}
			foreach my $p (@requested) {
				my $t = $p;
				$t =~ s/^no_//i;
				if (grep /^$t$/i, @G::tls_supported_protocols) {
					push(@G::tls_protocols, $p);
				} else {
					ptrans(12, "$p in --tls-protocol is not a known/supported protocol");
				}
			}
			if (!scalar(@G::tls_protocols)) {
				ptrans(12, "no valid arguments provided to --tls-protocol, exiting");
				exit(1);
			}
		}

		$G::tls_get_peer_cert = get_arg('tls_get_peer_cert', $o);
		$G::tls_get_peer_cert = 'STDOUT' if (defined($G::tls_get_peer_cert) && !length($G::tls_get_peer_cert));
	}

	# SMTP port
	if ($G::link{port}) {
		if ($G::link{port} !~ /^\d+$/) {
			if (my $port = getservbyname($G::link{port}, 'tcp')) {
				$G::link{port} = $port;
			}
			else {
				ptrans(12, "unable to resolve service name $G::link{port} into a port, exiting");
				exit(1);
			}
		}
	} else {
		# in here, user wants us to use default ports, so try look up services,
		# use default numbers is service names don't resolve.  Never prompt user
		if ($G::protocol eq 'lmtp') {
			$G::link{port} = getservbyname('lmtp',  'tcp') || '24';
		} elsif ($G::tls_on_connect) {
			$G::link{port} = getservbyname('smtps', 'tcp') || '465';
		} else {
			$G::link{port} = getservbyname('smtp',  'tcp') || '25';
		}
	}

	# XCLIENT
	{ # Create a block for local variables
		$G::xclient{try}     = 0;
		$G::xclient{attr}    = {};
		$G::xclient{strings} = [];
		my @pieces           = ();
		my $xclient_accum    = get_accum('xclient_accum', $o);
		foreach my $attr (@$xclient_accum) {
			if ($attr eq 'xclient_delim' || $attr eq 'xclient_raw') {
				if (scalar(@pieces)) {
					push(@{$G::xclient{strings}}, join(' ', @pieces));
					@pieces = ();
				}

				if ($attr eq 'xclient_raw') {
					push(@{$G::xclient{strings}}, get_arg('xclient_raw', $o));
				}
			} else {
				if (my $value = get_arg($attr, $o)) {
					$attr =~ /^xclient_(.*)$/;
					my $name = uc($1);
					$G::xclient{attr}{$name} = 1; # used later to verify that we haven't asked for an un-advertised attr
					push(@pieces, $name . '=' . to_xtext($value));
				}
			}
		}
		push(@{$G::xclient{strings}}, join(' ', @pieces)) if (scalar(@pieces));
		$G::xclient{no_verify}  = get_arg('xclient_no_verify', $o);
		$G::xclient{optional}   = get_arg('xclient_optional', $o);
		$G::xclient{optional}   = 2 if (get_arg('xclient_optional_strict', $o));
		#$G::xclient{after}      = $o->{"xclient_after"} || interact("XCLIENT quit after: ", '^.+$')
		#	if (defined($o->{"xclient_after"}));
		$G::xclient{try}        = 1 if (scalar(@{$G::xclient{strings}}));
		$G::xclient{before_tls} = get_arg('xclient_before_starttls', $o);
	}

	# PROXY
	$G::proxy{try}     = 0;
	$G::proxy{attr}    = {};
	$G::proxy{version} = get_arg('proxy_version', $o);
	$G::proxy{raw}     = get_arg('proxy_raw', $o);
	foreach my $attr ('family', 'source', 'source_port', 'dest', 'dest_port', 'protocol', 'command') {
		if (my $val = get_arg('proxy_' . $attr, $o)) {
			if ($G::proxy{raw}) {
				ptrans(12, "Can't mix --proxy option with other --proxy-* options");
				exit(35);
			}
			$G::proxy{attr}{$attr} = $val;
		}
	}
	if ($G::proxy{version}) {
		if ($G::proxy{version} != 1 && $G::proxy{version} != 2) {
			ptrans(12, "Invalid argument to --proxy: $G::proxy{version} is not a legal proxy version");
			exit(35);
		}
	}
	else {
		$G::proxy{version} = 1;
	}
	$G::proxy{try}       = 1 if ($G::proxy{raw} || scalar(keys(%{$G::proxy{attr}})));
	if ($G::proxy{try} && !$G::proxy{raw}) {
		$G::proxy{attr}{protocol} ||= 'STREAM';
		$G::proxy{attr}{command}  ||= 'PROXY';
		foreach my $attr ('family', 'source', 'source_port', 'dest', 'dest_port', 'protocol', 'command') {
			if (!$G::proxy{attr}{$attr}) {
				ptrans(12, "Incomplete set of --proxy-* options (missing $attr)");
				exit(35);
			}
			$G::proxy{attr}{$attr} = uc($G::proxy{attr}{$attr});
		}
		if ($G::proxy{attr}{protocol} !~ /^(UNSPEC|STREAM|DGRAM)$/) {
			ptrans(12, 'unknown --proxy-protocol argument ' . $G::proxy{attr}{protocol});
			exit(35);
		}
		if ($G::proxy{attr}{command} !~ /^(LOCAL|PROXY)$/) {
			ptrans(12, 'unknown --proxy-command argument ' . $G::proxy{attr}{command});
			exit(35);
		}
		if ($G::proxy{version} == 2 && $G::proxy{attr}{family} !~ /^(AF_UNSPEC|AF_INET|AF_INET6|AF_UNIX)$/) {
			ptrans(12, 'unknown --proxy-family argument ' . $G::proxy{attr}{family} . ' for version 2');
			exit(35);
		}
		if ($G::proxy{version} == 1 && $G::proxy{attr}{family} !~ /^(TCP4|TCP6)$/) {
			ptrans(12, 'unknown --proxy-family argument ' . $G::proxy{attr}{family} . ' for version 1');
			exit(35);
		}
	}

	# Handle AUTH options
	# auth_optional => 0 - no.     Auth must be advertised and must succeed, else error.
	#                  1 - yes.    Success if not advertised, advertised and fails _or_ succeeds.
	#                  2 - strict. Satisfied if not advertised, or advertised and succeeded.
	#                              However, if it's advertised and fails, it's an error.
	$G::auth_optional        = 1 if (defined($auth_optional_t));
	$G::auth_optional        = 2 if (defined($auth_optional_strict_t));
	my $auth_types_t         = [];
	if ($auth_t) {
		@{$auth_types_t} = map { uc($_) } (split(/,/, $auth_t));
	} elsif ($auth_optional_strict_t) {
		@{$auth_types_t} = map { uc($_) } (split(/,/, $auth_optional_strict_t));
	} elsif ($auth_optional_t) {
		@{$auth_types_t} = map { uc($_) } (split(/,/, $auth_optional_t));
	} elsif (defined($auth_user_t) || defined($auth_pass_t) || $G::auth_optional || (defined($auth_t) && !$auth_t)) {
		$auth_types_t->[0] = 'ANY';
		$auth_t            = 'ANY'; # this is checked below
		$G::auth_type      = 'ANY';
	}
	# if after that processing we've defined some auth type, do some more
	# specific processing
	if (scalar(@{$auth_types_t})) {
		# there's a lot of option processing below.  If any type looks like it
		# will succeed later, set this to true
		my $valid_auth_found = 0;

		# handle the --auth-map options plus our default mappings
		foreach (split(/\s*,\s*/, get_arg('auth_map', $o)),"PLAIN=PLAIN","LOGIN=LOGIN",
		                          "CRAM-MD5=CRAM-MD5","DIGEST-MD5=DIGEST-MD5",
		                          "CRAM-SHA1=CRAM-SHA1","NTLM=NTLM","SPA=NTLM","MSN=NTLM")
		{
			if (/^([^=]+)=(.+)$/) {
				my($alias,$type)        = ($1,$2);
				$G::auth_map_f{$alias}  = $type; # this gives us a list of all aliases pointing to types
				$G::auth_map_t{$type} ||= [];    # this gives a list of all base types and any aliases for it.
				push(@{$G::auth_map_t{$type}}, $alias);
			} else {
				ptrans(12, "Unknown auth-map format '$_'");
				exit(1);
			}
		}
		# Now handle the --auth-extra options
		foreach (split(/\s*,\s*/, get_arg('auth_extra', $o))) {
			if (/^([^=]+)=(.+)$/) {
				$G::auth_extras{uc($1)} = $2;
			} else {
				ptrans(12, "Unknown auth-extra format '$_'");
				exit(1);
			}
		}
		# handle the realm/domain synonyms
		if ($G::auth_extras{DOMAIN}) {
			$G::auth_extras{REALM}  = $G::auth_extras{DOMAIN};
		} elsif ($G::auth_extras{DOMAIN}) {
			$G::auth_extras{DOMAIN} = $G::auth_extras{REALM};
		}
		if (!avail("auth")) { # check for general auth requirements
			if ($G::auth_optional == 2) {
				# we don't know yet if this is really an error.  If the server
				# doesn't advertise auth, then it's not really an error.  So just
				# save it in case we need it later
				$G::auth_unavailable = avail_str("auth");
				ptrans(12, avail_str("auth"));
			} elsif ($G::auth_optional == 1) {
				ptrans(12, avail_str("auth"). ".  Skipping optional AUTH");
			} else {
				ptrans(12, avail_str("auth"). ".  Exiting");
				exit(10);
			}
		} else {
			# if the user doesn't specify an auth type, create a list from our
			# auth-map data.  Simplifies processing later
			if ($auth_types_t->[0] eq 'ANY') {
				$auth_types_t = [sort keys %G::auth_map_f];
			}

			foreach my $type (@{$auth_types_t}) {
				# we need to evaluate whether we will be able to run the auth types
				# specified by the user
				if (!$G::auth_map_f{$type}) {
					ptrans(12, "$type is not a recognized auth type, skipping");
				} elsif ($G::auth_map_f{$type} eq 'CRAM-MD5'   && !avail("auth_cram_md5")) {
					ptrans(12, avail_str("auth_cram_md5"))   if ($auth_t ne 'ANY');
				} elsif ($G::auth_map_f{$type} eq 'CRAM-SHA1'  && !avail("auth_cram_sha1")) {
					ptrans(12, avail_str("auth_cram_sha1"))  if ($auth_t ne 'ANY');
				} elsif ($G::auth_map_f{$type} eq 'NTLM'       && !avail("auth_ntlm")) {
					ptrans(12, avail_str("auth_ntlm"))       if ($auth_t ne 'ANY');
				} elsif ($G::auth_map_f{$type} eq 'DIGEST-MD5' && !avail("auth_digest_md5")) {
					ptrans(12, avail_str("auth_digest_md5")) if ($auth_t ne 'ANY');
				} else {
					$valid_auth_found = 1;
					push(@{$n{a_type}}, $type);
				}
			}

			if (!$valid_auth_found) {
				ptrans(12, "No auth types supported");
				if ($G::auth_optional == 2) {
					$G::auth_unavailable .= "No auth types supported";
				} elsif ($G::auth_optional == 1) {
					$n{a_user} = $n{a_pass} = $n{a_type} = undef;
				} else {
					exit(10);
				}
			} else {
				$auth_user_t ||= obtain_from_netrc('login');
				if (!$auth_user_t) {
					my $cfg = { cfgs => OP_ARG_REQ|OP_FROM_PROMPT, prompt  => 'Username: ', match  => 'SKIP', okey => 'auth_user', akey => 'auth_user' };
					$auth_user_t = get_arg('auth_user', $o, $cfg, 1);
				}
				$n{a_user} = $auth_user_t eq '<>' ? '' : $auth_user_t;

				$auth_pass_t ||= obtain_from_netrc('password', $n{a_user});
				if (!$auth_pass_t) {
					my $cfg = { cfgs => OP_ARG_REQ|OP_FROM_PROMPT|OP_SENSITIVE, prompt  => 'Password: ', match  => 'SKIP', okey => 'auth_pass', akey => 'auth_pass' };
					$auth_pass_t = get_arg('auth_pass', $o, $cfg, 1);
				}
				$n{a_pass} = $auth_pass_t eq '<>' ? '' : $auth_pass_t;

				$G::auth_showpt = get_arg('auth_showpt', $o);
				$G::auth_hidepw = get_arg('auth_hidepw', $o);
				if (defined($G::auth_hidepw) && !$G::auth_hidepw) {
					$G::auth_hidepw = 'PROVIDED_BUT_REMOVED';
				}
			}
		} # end avail("auth")
	} # end auth parsing

	# the very last thing we do is swap out the body if --dump-as-body used
	if (defined($dump_as_body)) {
		if ($dump_as_body) {
			$dump_as_body = uc($dump_as_body);
			$dump_as_body =~ s/\s//g;
			map { $G::dump_as_body{$_} = 1; } (split(',', $dump_as_body));
		}
		else {
			$G::dump_as_body{'ALL'} = 1;
		}

		$n{data} =~ s|DUMP_AS_BODY_HAS_BEEN_SET|get_running_state(\%n, \%G::dump_as_body, {SUPPORT => 1, DATA => 1})|e;
		if ($dab_sp) {
			$n{data} =~ s|'%RAW_PASSWORD_STRING%'|shquote($n{a_pass})|eg;
		} elsif ($G::auth_hidepw) {
			$n{data} =~ s|'%RAW_PASSWORD_STRING%'|shquote($G::auth_hidepw)|eg;
		} else {
			$n{data} =~ s|'%RAW_PASSWORD_STRING%'|shquote('PROVIDED_BUT_REMOVED')|eg;
		}
	}

	return(\%n);
}

sub encode_mime_part {
	my $part           = shift;
	my $boundary       = shift;
	my $no_attach_text = shift; # if this is true and there's no name, Don't set disposition to attachment
	my $text           = '';

	$text .= "--$boundary\n";
	if ($part->{type} =~ m|^text/plain$|i && !$part->{name}) {
		$text .= "Content-Type: $part->{type}\n\n" . $part->{body} . "\n";
	}
	else {
		if ($part->{name}) {
			$text .= "Content-Type: $part->{type}; name=\"$part->{name}\"\n"
			      .  "Content-Description: $part->{name}\n"
			      .  "Content-Disposition: attachment; filename=\"$part->{name}\"\n";
		}
		else {
			$text .= "Content-Type: $part->{type}\n";
			if (!($part->{type} =~ m|^text/|i && $no_attach_text)) {
				$text .= "Content-Disposition: attachment\n";
			}
		}
		$text .= "Content-Transfer-Encoding: BASE64\n"
		      .  "\n" . eb64($part->{body}, "\n") . "\n";
	}


	return($text);
}

sub parse_server {
	my $server = shift;
	my $port   = shift;

	if ($server =~ m|^\[([^\]]+)\]:(.*)$|) {
		# [1.2.3.4]:25
		# [hostname]:25
		# [1:2::3]:25
		return($1, $2);
	} elsif ($server =~ m|^([^:]+):([^:]+)$|) {
		# 1.2.3.4:25
		# hostname:25
		return($1, $2);
	} elsif ($server =~ m|^\[?([^/\]]*)\]?/(\w+)$|) {
		# 1.2.3.4/25   [1.2.3.4]/25
		# hostname/25  [hostname]/25
		# 1:2::3/25    [1:2::3]/25
		return($1, $2);
	} elsif ($server =~ m|^\[([^\]]+)\]$|) {
		# [1.2.3.4]
		# [hostname]
		# [1:2::3]
		return($1, $port);
	}
	return($server, $port);
}

sub get_running_state {
	my $opts      = shift;
	my $dump_args = shift;
	my $skip      = shift;
	my @parts     = ();

	if (($dump_args->{'SUPPORT'} || $dump_args->{'ALL'}) && !$skip->{'SUPPORT'}) {
		push(@parts, test_support(1));
	}

	if ($dump_args->{'APP'} || $dump_args->{'ALL'}) {
		push(@parts, [
			'App Info:',
			"  X-Mailer = $p_name v$p_version jetmore.org/john/code/swaks/",
			'  Cmd Line = ' . $0 . ' ' . $G::cmdline,
		]);
	}

	if ($dump_args->{'OUTPUT'} || $dump_args->{'ALL'}) {
		push(@parts, [
			'Output Info:',
			'  show_time_lapse    = ' . ($G::show_time_lapse    ? "TRUE ($G::show_time_lapse)"  : 'FALSE'),
			'  show_raw_text      = ' . ($G::show_raw_text      ? 'TRUE' : 'FALSE'),
			'  suppress_data      = ' . ($G::suppress_data      ? 'TRUE' : 'FALSE'),
			'  protect_prompt     = ' . ($G::protect_prompt     ? 'TRUE' : 'FALSE'),
			'  no_hints_send      = ' . ($G::no_hints_send      ? 'TRUE' : 'FALSE'),
			'  no_hints_recv      = ' . ($G::no_hints_recv      ? 'TRUE' : 'FALSE'),
			'  no_hints_info      = ' . ($G::no_hints_info      ? 'TRUE' : 'FALSE'),
			"  silent             = $G::silent",
			'  dump_mail          = ' . ($G::dump_mail          ? 'TRUE' : 'FALSE'),
			'  hide_send          = ' . ($G::hide_send          ? 'TRUE' : 'FALSE'),
			'  hide_receive       = ' . ($G::hide_receive       ? 'TRUE' : 'FALSE'),
			'  hide_informational = ' . ($G::hide_informational ? 'TRUE' : 'FALSE'),
			'  hide_all           = ' . ($G::hide_all           ? 'TRUE' : 'FALSE'),
			"  trans_fh_of        = $G::trans_fh_of ($G::trans_fh_oh," . \*STDOUT . ')',
			"  trans_fh_ef        = $G::trans_fh_ef ($G::trans_fh_eh," . \*STDERR . ')',
		]);
	}

	if ($dump_args->{'TRANSPORT'} || $dump_args->{'ALL'}) {
		push(@parts, [
			'Transport Info:',
			"  type            = $G::link{type}"
		]);
		if ($G::link{type} eq 'socket-inet') {
			push(@{$parts[-1]},
				'  inet protocol   = ' . ($G::link{force_ipv4} ? '4' : ($G::link{force_ipv6} ? '6' : 'any')),
				"  server          = $G::link{server}",
				"  port            = $G::link{port}",
				"  local interface = $G::link{lint}",
				"  local port      = $G::link{lport}",
				'  copy routing    = ' . ($opts->{copy_routing} ?  $opts->{copy_routing} : 'FALSE'),
			);
		}
		elsif ($G::link{type} eq 'socket-unix') {
			push(@{$parts[-1]}, "  sockfile        = $G::link{sockfile}");
		}
		elsif ($G::link{type} eq 'pipe') {
			push(@{$parts[-1]}, "  process         = $G::link{process}");
		}
		else {
			push(@{$parts[-1]}, "  UNKNOWN TRANSPORT TYPE");
		}
	}

	if ($dump_args->{'PROTOCOL'} || $dump_args->{'ALL'}) {
		push(@parts, [
			'Protocol Info:',
			"  protocol        = $G::protocol",
			"  helo            = $opts->{helo}",
			"  from            = $opts->{from}",
			"  to              = $opts->{to}",
			'  force getpwuid  = ' . ($opts->{force_getpwuid} ? 'TRUE' : 'FALSE'),
			"  quit after      = $G::quit_after",
			"  drop after      = $G::drop_after",
			"  drop after send = $G::drop_after_send",
			'  server_only     = ' . ($G::server_only ? 'TRUE' : 'FALSE'),
			"  timeout         = $G::link{timeout}",
			'  pipeline        = ' . ($G::pipeline    ? 'TRUE' : 'FALSE'),
			'  prdr            = ' . ($G::prdr        ? 'TRUE' : 'FALSE'),
		]);
	}

	if ($dump_args->{'XCLIENT'} || $dump_args->{'ALL'}) {
		push(@parts, ['XCLIENT Info:']);
		if ($G::xclient{try}) {
			if ($G::xclient{optional} == 2)    { push(@{$parts[-1]}, '  xclient         = optional-strict'); }
			elsif ($G::xclient{optional} == 1) { push(@{$parts[-1]}, '  xclient         = optional');        }
			else                               { push(@{$parts[-1]}, '  xclient         = required');        }
			push(@{$parts[-1]},
				'  no_verify       = ' . ($G::xclient{no_verify}  ? 'TRUE' : 'FALSE'),
				'  before starttls = ' . ($G::xclient{before_tls} ? 'TRUE' : 'FALSE'),
			);
			for (my $i = 0; $i < scalar(@{$G::xclient{strings}}); $i++) {
				my $prefix = $i ? '                   ' : '  strings         =';
				push(@{$parts[-1]}, "$prefix XCLIENT $G::xclient{strings}[$i]");
			}
		} else {
			push(@{$parts[-1]}, '  xclient = no');
		}
	}

	if ($dump_args->{'PROXY'} || $dump_args->{'ALL'}) {
		push(@parts, ['PROXY Info:']);
		if ($G::proxy{try}) {
			push(@{$parts[-1]}, '  proxy       = yes');
			push(@{$parts[-1]}, "  version     = $G::proxy{version}");
			if ($G::proxy{raw}) {
				push(@{$parts[-1]}, "  raw string  = $G::proxy{raw}");
			} else {
				push(@{$parts[-1]},
					'  family      = ' . $G::proxy{attr}{family},
					'  source      = ' . $G::proxy{attr}{source},
					'  source port = ' . $G::proxy{attr}{source_port},
					'  dest        = ' . $G::proxy{attr}{dest},
					'  dest port   = ' . $G::proxy{attr}{dest_port},
					'  protocol    = ' . $G::proxy{attr}{protocol},
					'  command     = ' . $G::proxy{attr}{command},
				);
			}
		} else {
			push(@{$parts[-1]}, '  proxy = no');
		}
	}

	if ($dump_args->{'TLS'} || $dump_args->{'ALL'}) {
		push(@parts, ['TLS / Encryption Info:']);
		if ($G::tls || $G::tls_on_connect) {
			if ($G::tls) {
				if ($G::tls_optional == 2)    { push(@{$parts[-1]}, '  tls                 = starttls (optional-strict)'); }
				elsif ($G::tls_optional == 1) { push(@{$parts[-1]}, '  tls                 = starttls (optional)');        }
				else                          { push(@{$parts[-1]}, '  tls                 = starttls (required)');        }
			}
			elsif ($G::tls_on_connect)        { push(@{$parts[-1]}, '  tls                 = starttls on connect (required)'); }
			push(@{$parts[-1]},
				"  peer cert           = $G::tls_get_peer_cert",
				"  local cert          = $G::tls_cert",
				"  local key           = $G::tls_key",
				"  local cipher list   = $G::tls_cipher",
				"  ca path             = $G::tls_ca_path",
				"  sni string          = $G::tls_sni_hostname",
				'  verify server cert  = ' . ($G::tls_verify ? 'TRUE' : 'FALSE'),
				'  available protocols = ' . join(', ', @G::tls_supported_protocols),
				'  requested protocols = ' . join(', ', @G::tls_protocols),
			);
		}
		else {
			push(@{$parts[-1]}, '  tls = no');
		}
	}

	if ($dump_args->{'AUTH'} || $dump_args->{'ALL'}) {
		push(@parts, ['Authentication Info:']);
		if ($opts->{a_type}) {
			if ($G::auth_optional == 2)    { push(@{$parts[-1]}, '  auth           = optional-strict'); }
			elsif ($G::auth_optional == 1) { push(@{$parts[-1]}, '  auth           = optional');        }
			else                           { push(@{$parts[-1]}, '  auth           = required');        }
			push(@{$parts[-1]},
				"  username       = '$opts->{a_user}'",
				"  password       = '%RAW_PASSWORD_STRING%'",
				'  show plaintext = ' . ($G::auth_showpt ? 'TRUE' : 'FALSE'),
				'  hide password  = ' . ($G::auth_hidepw ? $G::auth_hidepw : 'FALSE'),
				'  allowed types  = ' . join(', ', @{$opts->{a_type}}),
				'  extras         = ' . join(', ', map { "$_=$G::auth_extras{$_}" } (sort(keys((%G::auth_extras))))),
				'  type map       = ' . join("\n".' 'x19, map { "$_ = ". join(', ', @{$G::auth_map_t{$_}}) } (sort(keys(%G::auth_map_t)))),
			);
		}
		else {
			push(@{$parts[-1]}, "  auth = no");
		}
	}

	if (($dump_args->{'DATA'} || $dump_args->{'ALL'}) && !$skip->{'DATA'}) {
		push(@parts, [
			'DATA Info:',
			'  data = <<.',
			$opts->{data}
		]);
	}

	# rejoin the parts into a string now
	# this whole exercise was to avoid extra newlines when only dumping certain parts
	foreach my $part (@parts) {
		$part = join("\n", @$part) . "\n";
	}
	return(join("\n", @parts));
}

sub get_username {
	my $force_getpwuid = shift;
	if ($^O eq 'MSWin32') {
		require Win32;
		return Win32::LoginName();
	}
	if ($force_getpwuid) {
		return (getpwuid($<))[0];
	}
	return $ENV{LOGNAME} || (getpwuid($<))[0];
}

sub get_date_string {
	return($G::date_string) if (length($G::date_string) > 0);

	my $et          = time();
	my @month_names = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	my @day_names   = qw(Sun Mon Tue Wed Thu Fri Sat);

	if (!avail("date_manip")) {
		ptrans(12, avail_str("date_manip").".  Date strings will be in GMT");
		my @l = gmtime($et);
		$G::date_string = sprintf("%s, %02d %s %d %02d:%02d:%02d %+05d",
		                          $day_names[$l[6]],
		                          $l[3],
		                          $month_names[$l[4]],
		                          $l[5]+1900, $l[2], $l[1], $l[0],
		                          0);
	} else {
		# this is convoluted because %a (week day name) and %b (month name) are localized, but per RFC they should be in English. Since
		# un-localizing didn't work on every system I tested, jump through hoops here to not use those fields at all.
		my @l = localtime($et);
		$G::date_string = sprintf("%s, %s %s %s",
			                      $day_names[POSIX::strftime("%w", @l)],
			                      POSIX::strftime("%d", @l),
			                      $month_names[POSIX::strftime("%m", @l) - 1],
			                      POSIX::strftime("%Y %H:%M:%S %z", @l));
	}
	return($G::date_string);
}

# partially Cribbed from "Programming Perl" and MIME::Base64 v2.12
sub db64 {
	my $s =  shift;
	if (load("MIME::Base64")) {
		return(decode_base64($s));
	} else {
		$s =~ tr#A-Za-z0-9+/##cd;
		$s =~ s|=+$||;
		$s =~ tr#A-Za-z0-9+/# -_#;
		my $r = '';
		while ($s =~ s/(.{1,60})//s) {
			$r .= unpack("u", chr(32 + int(length($1)*3/4)) . $1);
		}
		return($r);
	}
}

# partially Cribbed from MIME::Base64 v2.12
sub eb64 {
	my $s =  shift;
	my $e =  shift || ''; # line ending to use "empty by default"
	if (load("MIME::Base64")) {
		return(encode_base64($s, $e));
	} else {
		my $l =  length($s);
		chomp($s = pack("u", $s));
		$s =~ s|\n.||gms;
		$s =~ s|\A.||gms;
		$s =~ tr#` -_#AA-Za-z0-9+/#;
		my $p = (3 - $l%3) % 3;
		$s =~ s/.{$p}$/'=' x $p/e if ($p);
		$s =~ s/(.{1,76})/$1$e/g  if (length($e));
		return($s);
	}
}

sub build_version {
	my $static = shift;
	my $svn    = shift;

	if ($static ne 'DEVRELEASE') {
		# if gen-util passed in a static version, use it unconditionally
		return $static;
	} elsif ($svn =~ /\$Id:\s+\S+\s+(\d+)\s+(\d+)-(\d+)-(\d+)\s+/) {
		# otherwise, this is a dev copy, dynamically build a version string for it
		return("$2$3$4.$1-dev");
	} else {
		# we wanted a dynamic version, but the SVN Id tag wasn't in the format
		# we expected, punt
		return("DEVRELEASE");
	}
}

sub ext_usage {
	require Config;
	$ENV{PATH} .= ":" unless $ENV{PATH} eq "";
	$ENV{PATH}  = $ENV{PATH} . $Config::Config{'installscript'};
	$< = $> = 1 if ($> == 0 || $< == 0);
	exec("perldoc", $0) || exit(1);
	# make parser happy
	%Config::Config = ();

	exit(0);
}


=pod

=head1 NAME

Swaks - Swiss Army Knife SMTP, the all-purpose SMTP transaction tester

=head1 DESCRIPTION

Swaks' primary design goal is to be a flexible, scriptable, transaction-oriented SMTP test tool.  It handles SMTP features and extensions such as TLS, authentication, and pipelining; multiple version of the SMTP protocol including SMTP, ESMTP, and LMTP; and multiple transport methods including UNIX-domain sockets, internet-domain sockets, and pipes to spawned processes.  Options can be specified in environment variables, configuration files, and the command line allowing maximum configurability and ease of use for operators and scripters.

=head1 QUICK START

Deliver a standard test email to user@example.com on port 25 of test-server.example.net:

=over 4

 swaks --to user@example.com --server test-server.example.net

=back

Deliver a standard test email, requiring CRAM-MD5 authentication as user me@example.com.  An "X-Test" header will be added to the email body.  The authentication password will be prompted for if it cannot be obtained from your L<.netrc|Net::Netrc> file.

=over 4

 swaks --to user@example.com --from me@example.com --auth CRAM-MD5 --auth-user me@example.com --header-X-Test "test email"

=back

Test a virus scanner using EICAR in an attachment.  Don't show the message DATA part.:

=over 4

 swaks -t user@example.com --attach - --server test-server.example.com --suppress-data </path/to/eicar.txt

=back

Test a spam scanner using GTUBE in the body of an email, routed via the MX records for example.com:

=over 4

 swaks --to user@example.com --body /path/to/gtube/file

=back

Deliver a standard test email to user@example.com using the LMTP protocol via a UNIX domain socket file

=over 4

 swaks --to user@example.com --socket /var/lda.sock --protocol LMTP

=back

Report all the recipients in a text file that are non-verifiable on a test server:

=over 4

 for E in `cat /path/to/email/file`
 do
     swaks --to $E --server test-server.example.com --quit-after RCPT --hide-all
     [ $? -ne 0 ] && echo $E
 done

=back

=head1 TERMS AND CONVENTIONS

This document tries to be consistent and specific in its use of the following terms to reduce confusion.

=over 4

=item Target

The target of a transaction is the thing that Swaks connects to.  This generic term is used throughout the documentation because most other terms improperly imply something about the transport being used.

=item Transport

The transport is the underlying method used to connect to the target.

=item Transaction

A transaction is the opening of a connection over a transport to a target and using a messaging protocol to attempt to deliver a message.

=item Protocol

The protocol is the application language used to communicate with the target.  This document uses SMTP to speak generically of all three supported protocols unless it states that it is speaking of the specific 'SMTP' protocol and excluding the others.

=item Message

SMTP protocols exist to transfer messages, a set of bytes in an agreed-upon format that has a sender and a recipient.

=item Envelope

A message's envelope contains the "true" sender and receiver of a message.  It can also be referred to as its components, envelope-sender and envelope-recipients.  It is important to note that a messages envelope does not have to match its C<To:> and C<From:> headers.

=item DATA

The DATA portion of an SMTP transaction is the actual message that is being transported.  It consists of both the message's headers and its body.  DATA and body are sometimes used synonymously, but they are always two distinct things in this document.

=item Headers

A message's headers are defined as all the lines in the message's DATA section before the first blank line.  They contain information about the email that will be displayed to the recipient such as C<To:>, C<From:>, C<Subject:>, etc.  In this document headers will always be written with a capitalized first letter and a trailing colon.

=item Body

A message's body is the portion of its DATA section following the first blank line.

=item Option

An option is a flag which changes Swaks' behavior.  Always called an option regardless of how it is provided.  For instance, C<--no-data-fixup> is an option.

=item Argument

When an option takes addition data beside the option itself, that additional data is called an argument. In C<< --quit-after <stop-point>' >>, C<< <stop-point> >> is the argument to the C<--quit-after> option.

=item <literal-string>

When used in the definition of an option, text that is inside of angle brackets (C<< <> >>) indicates a descriptive label for a value that the user should provide.  For instance, C<< --quit-after <stop-point> >> indicates that C<< <stop-point> >> should be replaced with a valid stop-point value.

=item [<optional-value>]

When used in the definition of an option, text inside of square brackets ([]) indicates that the value is optional and can be omitted.  For instance, C<< --to [<recipient>] >> indicates that the C<--to> option can be used with or without a specified C<< <recipient> >>.

=back

=head1 OPTION PROCESSING

To prevent potential confusion in this document a flag to Swaks is always referred to as an "option".  If the option takes additional data, that additional data is referred to as an argument to the option.  For example, C<--from fred@example.com> might be provided to Swaks on the command line, with C<--from> being the option and C<fred@example.com> being C<--from>'s argument.

Options and arguments are the only way to provide information to Swaks.  If Swaks finds data during option processing that is neither an option nor an option's argument, it will error and exit.  For instance, if C<--no-data-fixup 1> were found on the command line, this would result in an error because C<--no-data-fixup> does not take an argument and therefore Swaks would not know what to do with C<1>.

Options can be given to Swaks in three ways.  They can be specified in a configuration file, in environment variables, and on the command line.  Depending on the specific option and whether an argument is given to it, Swaks may prompt the user for the argument.

When Swaks evaluates its options, it first looks for a configuration file (either in a default location or specified with C<--config>).  Then it evaluates any options in environment variables.  Finally, it evaluates command line options.  At each round of processing, any options set earlier will be overridden.  Additionally, any option can be prefixed with C<no-> to cause Swaks to forget that the variable had previously been set (either in an earlier round, or earlier in the same round).  This capability is necessary because many options treat defined-but-no-argument differently than not-defined.

As a general rule, if the same option is given multiple time, the last time it is given is the one that will be used.  This applies to both intra-method (if C<--from user1@example.com --from user2@example.com> is given, C<user2@example.com> will be used) and inter-method (if C<from user1@example.com> is given in a config file and C<--from user2@example.com> is given on the command line, C<user2@example.com> will be used)

Each option definition ends with a parenthetical synopsis of how the option behaves.  The following codes can be used

=over 4

=item Arg-None, Arg-Optional, Arg-Required

These three codes are mutually exclusive and describe whether or not the option takes an argument.  Note that this does not necessarily describe whether the argument is required to be specified directly, but rather whether an argument is required eventually.  For instance, C<--to> is labeled as Arg-Required, but it is legal to specify C<--to> on the command line without an argument.  This is because Swaks can prompt for the required argument if it is not directly provided.

=item From-Prompt

An option labeled with From-Prompt will prompt the user interactively for the argument if none is provided.

=item From-File

An option labeled with From-File will handle arguments as files in certain situations.

If the initial argument is C<->, the final argument is the contents of C<STDIN>.  Multiple options can all specify C<STDIN>, but the same content will be used for each of them.

If the initial argument is prefixed with C<@>, the argument will be treated as a path to a file.  The file will be opened and the contents will be used as the final argument.  If the contents of the file can't be read, Swaks will exit.  To specify a literal value starting with an C<@>, use two C<@> symbols.  The first will be stripped.

=item Sensitive

If an option marked Sensitive attempts to prompt the user for an argument and the C<--protect-prompt> option is set, Swaks will attempt to mask the user input from being echoed on the terminal.  Swaks tries to mask the input in several ways, but if none of them work program flow will continue with unmasked input.

=item Deprecated

An option labeled Deprecated has been officially deprecated and will be removed in a future release.  See the L</DEPRECATIONS> section of this documentation for details about the deprecations.

=back

The exact mechanism and format for using each of the types is listed below.

=over 4

=item CONFIGURATION FILES

A configuration file can be used to set commonly-used or abnormally verbose options.  By default, Swaks looks in order for F<$SWAKS_HOME/.swaksrc>, F<$HOME/.swaksrc>, and F<$LOGDIR/.swaksrc>.  If one of those is found to exist (and C<--config> has not been used) that file is used as the configuration file.

Additionally, a configuration file in a non-default location can be specified using C<--config>.  If this is set and not given an argument Swaks will not use any configuration file, including any default file.  If C<--config> points to a readable file, it is used as the configuration file, overriding any default that may exist.  If it points to a non-readable file an error will be shown and Swaks will exit.

A set of "portable" defaults can also be created by adding options to the end of the Swaks program file.  As distributed, the last line of Swaks should be C<__END__>.  Any lines added after C<__END__> will be treated as the contents of a configuration file.  This allows a set of user preferences to be automatically copied from server to server in a single file.

If configuration files have not been explicitly turned off, the C<__END__> config is always read.  Only one other configuration file will ever be used per single invocation of Swaks, even if multiple configuration files are specified.  If the C<__END__> config and another config are to be read, the C<__END__> config will be processed first.  Specifying the C<--config> option with no argument turns off the processing of both the C<__END__> config and any actual config files.

In a configuration file lines beginning with a hash (C<#>) are ignored.  All other lines are assumed to be an option to Swaks, with the leading dash or dashes optional.  Everything after an option line's first space is assumed to be the option's argument and is not shell processed.  Therefore, quoting is usually unneeded and will be included literally in the argument.

There is a subtle difference between providing an option with no argument and providing an option with an empty argument.  If an option line does not have a space, the entire line is treated as an option and there is no argument.  If the line ends in a single space, it will be processed as an option with an empty argument.  So, C<apt> will be treated as C<--apt>, but C<apt > will be treated as C<S<--apt ''>>.

Here is an example of the contents of a configuration file:

    # always use this sender, no matter server or logged in user
    --from fred@example.com
    # I prefer my test emails have a pretty from header.  Note
    # the lack of dashes on option and lack of quotes around
    # entire argument.
    h-From: "Fred Example" <fred@example.com>

Options specific to configuration file:

=over 4

=item --config [<config-file>]

This option provides a path to a specific configuration file to be used.  If specified with no argument, no automatically-found configuration file (via C<$HOME>, etc, or C<__END__>) will be processed.  If the argument is a valid file, that file will be used as the configuration file (after C<__END__> config).  If argument is not a valid, readable file, Swaks will error and exit.  This option can be specified multiple times, but only the first time it is specified (in environment variable and the command line search order) will be used. (Arg-Optional)

=back

=item CONFIGURATION ENVIRONMENT VARIABLES

Options can be supplied via environment variables.  The variables are in the form C<$SWAKS_OPT_name>, where C<name> is the name of the option that would be specified on the command line.  Because dashes aren't allowed in environment variable names in most UNIX-ish shells, no leading dashes should be used and any dashes inside the option's name should be replaced with underscores.  The following would create the same options shown in the configuration file example:

    $ SWAKS_OPT_from='fred@example.com'
    $ SWAKS_OPT_h_From='"Fred Example" <fred@example.com>'

Setting a variable to an empty value is the same as specifying it on the command line with no argument.  For instance, setting <SWAKS_OPT_server=""> would cause Swaks to prompt the user for the server to which to connect at each invocation.

Because there is no inherent order in options provided by setting environment variables, the options are sorted before being processed.  This is not a great solution, but it at least defines the behavior, which would be otherwise undefined.  As an example, if both C<$SWAKS_OPT_from> and C<$SWAKS_OPT_f> were set, the value from C<$SWAKS_OPT_from> would be used, because it sorts after C<$SWAKS_OPT_f>.  Also as a result of not having an inherent order in environment processing, unsetting options with the C<no-> prefix is unreliable.  It works if the option being turned off sorts before C<no->, but fails if it sorts after. Because C<no-> is primarily meant to operate between config types (for instance, unsetting from the command line an option that was set in a config file), this is not likely to be a problem.

In addition to setting the equivalent of command line options, C<$SWAKS_HOME> can be set to a directory containing the default F<.swaksrc> to be used.

=item COMMAND LINE OPTIONS

The final method of supplying options to Swaks is via the command line.  The options behave in a manner consistent with most UNIX-ish command line programs.  Many options have both a short and long form (for instance C<-s> and C<--server>).  By convention short options are specified with a single dash and long options are specified with a double-dash.  This is only a convention and either prefix will work with either type.

The following demonstrates the example shown in the configuration file and environment variable sections:

    $ swaks --from fred@example.com --h-From: '"Fred Example" <fred@example.com>'

=back

=head1 TRANSPORTS

Swaks can connect to a target via UNIX pipes ("pipes"), UNIX domain sockets ("UNIX sockets"), or internet domain sockets ("network sockets").  Connecting via network sockets is the default behavior.  Because of the singular nature of the transport used, each set of options in the following section is mutually exclusive.  Specifying more than one of C<--server>, C<--pipe>, or C<--socket> will result in an error.  Mixing other options between transport types will only result in the irrelevant options being ignored.  Below is a brief description of each type of transport and the options that are specific to that transport type.

=over 4

=item NETWORK SOCKETS

This transport attempts to deliver a message via TCP/IP, the standard method for delivering SMTP.  This is the default transport for Swaks.  If none of C<--server>, C<--pipe>, or C<--socket> are given then this transport is used and the target server is determined from the recipient's domain (see C<--server> below for more details).

This transport requires the L<IO::Socket> module which is part of the standard Perl distribution.  If this module is not loadable, attempting to use this transport will result in an error and program termination.

IPv6 is supported when the L<IO::Socket::INET6> module is present.

=over 4

=item -s, --server [<target-server>[:<port>]]

Explicitly tell Swaks to use network sockets and specify the hostname or IP address to which to connect, or prompt if no argument is given.  If this option is not given and no other transport option is given, the target mail server is determined from the appropriate DNS records for the domain of the recipient email address using the L<Net::DNS> module.  If L<Net::DNS> is not available Swaks will attempt to connect to localhost to deliver.  The target port can optionally be set here.  Supported formats for this include SERVER:PORT (supporting names and IPv4 addresses); [SERVER]:PORT and SERVER/PORT (supporting names, IPv4 and IPv6 addresses).  See also C<--copy-routing>. (Arg-Required, From-Prompt)

=item -p, --port [<port>]

Specify which TCP port on the target is to be used, or prompt if no argument is listed.  The argument can be a service name (as retrieved by L<getservbyname(3)>) or a port number.  The default port is smtp/25 unless influenced by the C<--protocol> or C<--tls-on-connect> options. (Arg-Required, From-Prompt)

=item -li, --local-interface [<local-interface>[:<port>]]

Use argument as the local interface for the outgoing SMTP connection, or prompt user if no argument given.  Argument can be an IP address or a hostname.  Default action is to let the operating system choose the local interface.  See C<--server> for additional comments on :<port> format. (Arg-Required, From-Prompt)

=item -lp, --local-port, --lport [<port>]

Specify the outgoing port from which to originate the transaction.  The argument can be a service name (as retrieved by L<getservbyname(3)>) or a port number.  If this option is not specified the system will pick an ephemeral port.  Note that regular users cannot specify some ports. (Arg-Required, From-Prompt)

=item --copy-routing <domain>

The argument is interpreted as the domain part of an email address and it is used to find the target server using the same logic that would be used to look up the target server for a recipient email address.  See C<--to> option for more details on how the target is determined from the email domain. (Arg-Required)

=item -4, -6

Force IPv4 or IPv6. (Arg-None)

=back

=item UNIX SOCKETS

This transport method attempts to deliver messages via a UNIX-domain socket file.  This is useful for testing MTA/MDAs that listen on socket files (for instance, testing LMTP delivery to Cyrus).  This transport requires the L<IO::Socket> module which is part of the standard Perl distribution.  If this module is not loadable, attempting to use this transport will result in an error and program termination.

=over 4

=item --socket [<socket-file>]

This option takes as its argument a UNIX-domain socket file.  If Swaks is unable to open this socket it will display an error and exit. (Arg-Required, From-Prompt)

=back

=item PIPES

This transport attempts to spawn a process and communicate with it via pipes.  The spawned program must be prepared to behave as a mail server over C<STDIN>/C<STDOUT>.  Any MTA designed to operate from inet/xinet should support this.  In addition, some MTAs provide testing modes that can be communicated with via C<STDIN>/C<STDOUT>.  This transport can be used to automate that testing.  For example, if you implemented DNSBL checking with Exim and you wanted to make sure it was working, you could run C<swaks --pipe "exim -bh 127.0.0.2">.  Ideally, the process you are talking to should behave exactly like an SMTP server on C<STDIN> and C<STDOUT>.  Any debugging should be sent to C<STDERR>, which will be directed to your terminal.  In practice, Swaks can generally handle some debug on the child's C<STDOUT>, but there are no guarantees on how much it can handle.

This transport requires the L<IPC::Open2> module which is part of the standard Perl distribution.  If this module is not loadable, attempting to use this transport will result in an error and program termination.

=over 4

=item --pipe [<command-and-arguments>]

Provide a process name and arguments to the process.  Swaks will attempt to spawn the process and communicate with it via pipes.  If the argument is not an executable Swaks will display an error and exit. (Arg-Required, From-Prompt)

=back

=back

=head1 PROTOCOL OPTIONS

These options are related to the protocol layer.

=over 4

=item -t, --to [<email-address>[,<email-address>[,...]]]

Tells Swaks to use argument(s) as the envelope-recipient for the email, or prompt for recipient if no argument provided.  If multiple recipients are provided and the recipient domain is needed to determine routing the domain of the last recipient provided is used.

There is no default value for this option.  If no recipients are provided via any means, user will be prompted to provide one interactively.  The only exception to this is if a C<--quit-after> value is provided which will cause the SMTP transaction to be terminated before the recipient is needed. (Arg-Required, From-Prompt)

=item -f, --from [<email-address>]

Use argument as envelope-sender for email, or prompt user if no argument specified.  The string C<< <> >> can be supplied to mean the null sender.  If user does not specify a sender address a default value is used.  The domain-part of the default sender is a best guess at the fully-qualified domain name of the local host.  The method of determining the local-part varies.  On Windows, C<Win32::LoginName()> is used.  On UNIX-ish platforms, the C<$LOGNAME> environment variable is used if it is set.  Otherwise L<getpwuid(3)> is used.  See also C<--force-getpwuid>.  If Swaks cannot determine a local hostname and the sender address is needed for the transaction, Swaks will error and exit.  In this case, a valid string must be provided via this option. (Arg-Required, From-Prompt)

=item --ehlo, --lhlo, -h, --helo [<helo-string>]

String to use as argument to HELO/EHLO/LHLO command, or prompt user if no argument is specified.  If this option is not used a best guess at the fully-qualified domain name of the local host is used.  If Swaks cannot determine a local hostname and the helo string is needed for the transaction, Swaks will error and exit.  In this case, a valid string must be provided via this option. (Arg-Required, From-Prompt)

=item -q, --quit, --quit-after <stop-point>

Point at which the transaction should be stopped.  When the requested stopping point is reached in the transaction, and provided that Swaks has not errored out prior to reaching it, Swaks will send "QUIT" and attempt to close the connection cleanly.  These are the valid arguments and notes about their meaning. (Arg-Required)

=over 4

=item CONNECT, BANNER

Terminate the session after receiving the greeting banner from the target.

=item FIRST-HELO, FIRST-EHLO, FIRST-LHLO

In a STARTTLS (but not tls-on-connect) session, terminate the transaction after the first of two HELOs.  In a non-STARTTLS transaction, behaves the same as HELO (see below).

=item XCLIENT

Quit after XCLIENT is sent.

=item STARTTLS, TLS

Quit the transaction immediately following TLS negotiation.  Note that this happens in different places depending on whether STARTTLS or tls-on-connect are used.  This always quits after the point where TLS would have been negotiated, regardless of whether it was attempted.

=item HELO, EHLO, LHLO

In a STARTTLS or XCLIENT session, quit after the second HELO.  Otherwise quit after the first and only HELO.

=item AUTH

Quit after authentication.  This always quits after the point where authentication would have been negotiated, regardless of whether it was attempted.

=item MAIL, FROM

Quit after MAIL FROM: is sent.

=item RCPT, TO

Quit after RCPT TO: is sent.

=back

=item --da, --drop-after <stop-point>

The option is similar to C<--quit-after>, but instead of trying to cleanly shut down the session it simply terminates the session.  This option accepts the same stop-points as C<--quit-after> and additionally accepts DATA and DOT, detailed below. (Arg-Required)

=over 4

=item DATA

Quit after DATA is sent.

=item DOT

Quit after the final '.' of the message is sent.

=back

=item --das, --drop-after-send <stop-point>

This option is similar to C<--drop-after>, but instead of dropping the connection after reading a response to the stop-point, it drops the connection immediately after sending stop-point.  It accepts the same stop-points as C<--drop-after>. (Arg-Required)

=item --timeout [<time>]

Use argument as the SMTP transaction timeout, or prompt user if no argument given.  Argument can either be a pure digit, which will be interpreted as seconds, or can have a specifier s, m, or h (5s = 5 seconds, 3m = 180 seconds, 1h = 3600 seconds).  As a special case, 0 means don't timeout the transactions.  Default value is 30s. (Arg-Required, From-Prompt)

=item --protocol <protocol>

Specify which protocol to use in the transaction.  Valid options are shown in the table below.  Currently the 'core' protocols are SMTP, ESMTP, and LMTP.  By using variations of these protocol types one can tersely specify default ports, whether authentication should be attempted, and the type of TLS connection that should be attempted.  The default protocol is ESMTP.  The following table demonstrates the available arguments to C<--protocol> and the options each sets as a side effect.  (Arg-Required)

=over 4

=item SMTP

HELO, "-p 25"

=item SSMTP

EHLO-E<gt>HELO, "-tlsc -p 465"

=item SSMTPA

EHLO-E<gt>HELO, "-a -tlsc -p 465"

=item SMTPS

HELO, "-tlsc -p 465"

=item ESMTP

EHLO-E<gt>HELO, "-p 25"

=item ESMTPA

EHLO-E<gt>HELO, "-a -p 25"

=item ESMTPS

EHLO-E<gt>HELO, "-tls -p 25"

=item ESMTPSA

EHLO-E<gt>HELO, "-a -tls -p 25"

=item LMTP

LHLO, "-p 24"

=item LMTPA

LHLO, "-a -p 24"

=item LMTPS

LHLO, "-tls -p 24"

=item LMTPSA

LHLO, "-a -tls -p 24"

=back

=item --pipeline

If the remote server supports it, attempt SMTP PIPELINING (RFC 2920). (Arg-None)

=item --prdr

If the server supports it, attempt Per-Recipient Data Response (PRDR) (L<https://tools.ietf.org/html/draft-hall-prdr-00.txt>).  PRDR is not yet standardized, but MTAs have begun implementing the proposal. (Arg-None)

=item --force-getpwuid

Tell Swaks to use the getpwuid method of finding the default sender local-part instead of trying C<$LOGNAME> first. (Arg-None)

=back

=head1 TLS / ENCRYPTION

These are options related to encrypting the transaction.  These have been tested and confirmed to work with all three transport methods.  The L<Net::SSLeay> module is used to perform encryption when it is requested.  If this module is not loadable Swaks will either ignore the TLS request or error out, depending on whether the request was optional.  STARTTLS is defined as an extension in the ESMTP protocol and will be unavailable if C<--protocol> is set to a variation of SMTP.  Because it is not defined in the protocol itself, C<--tls-on-connect> is available for any protocol type if the target supports it.

A local certificate is not required for a TLS connection to be negotiated.  However, some servers use client certificate checking to verify that the client is allowed to connect.  Swaks can be told to use a specific local certificate using the C<--tls-cert> and C<--tls-key> options.

=over 4

=item -tls

Require connection to use STARTTLS.  Exit if TLS not available for any reason (not advertised, negotiations failed, etc). (Arg-None)

=item -tlso, --tls-optional

Attempt to use STARTTLS if available, continue with normal transaction if TLS was unable to be negotiated for any reason.  Note that this is a semi-useless option as currently implemented because after a negotiation failure the state of the connection is unknown.  In some cases, like a version mismatch, the connection should be left as plaintext.  In others, like a verification failure, the server-side may think that it should continue speaking TLS while the client thinks it is plaintext.  There may be an attempt to add more granular state detection in the future, but for now just be aware that odd things may happen with this option if the TLS negotiation is attempted and fails. (Arg-None)

=item -tlsos, --tls-optional-strict

Attempt to use STARTTLS if available.  Proceed with transaction if TLS is negotiated successfully or STARTTLS not advertised.  If STARTTLS is advertised but TLS negotiations fail, treat as an error and abort transaction.  Due to the caveat noted above, this is a much saner option than C<--tls-optional>. (Arg-None)

=item -tlsc, --tls-on-connect

Initiate a TLS connection immediately on connection.  Following common convention, if this option is specified the default port changes from 25 to 465, though this can still be overridden with the --port option. (Arg-None)

=item -tlsp, --tls-protocol <tls-version-specification>

Specify which protocols to use (or not use) when negotiating TLS.  At the time of this writing, the available protocols are sslv2, sslv3, tlsv1, tlsv1_1, tlsv1_2, and tlsv1_3.  The availability of these protocols is dependent on your underlying OpenSSL library, so not all of these may be available.  The list of available protocols is shown in the output of C<--dump> (assuming TLS is available at all).

The specification string is a comma-delimited list of protocols that can be used or not used.  For instance 'tlsv1,tlsv1_1' will only succeed if one of those two protocols is available on both the client and the server.  Conversely, 'no_sslv2,no_sslv3' will attempt to negotiate any protocol except sslv2 and sslv3.  The two forms of specification cannot be mixed. (Arg-Required)

=item --tls-cipher <cipher-string>

The argument to this option is passed to the underlying OpenSSL library to set the list of acceptable ciphers to the be used for the connection.  The format of this string is opaque to Swaks and is defined in L<http://www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT>.  A brief example would be C<--tls-cipher '3DES:+RSA'>. (Arg-Required)

=item --tls-verify

Tell Swaks to attempt to verify the server's certificate.  If this option is set and the server's certificate is not verifiable (either using the system-default CA information, or custom CA information (see C<--tls-ca-path>)) TLS negotiation will not succeed.  By default, Swaks does not attempt certificate verification. (Arg-None)

=item --tls-ca-path <ca-location>

Specify an alternate location for CA information for verifying server certificates.  The argument can point to a file or directory.  The default behavior is to use the underlying OpenSSL library's default information. (Arg-Required)

=item --tls-cert <cert-file>

Provide a path to a file containing the local certificate Swaks should use if TLS is negotiated.  The file path argument is required.  As currently implemented the certificate in the file must be in PEM format.  Contact the author if there's a compelling need for ASN1.  If this option is set, C<--tls-key> is also required. (Arg-Required)

=item --tls-key <key-file>

Provide a path to a file containing the local private key Swaks should use if TLS is negotiated.  The file path argument is required.  As currently implemented the certificate in the file must be in PEM format.  Contact the author if there's a compelling need for ASN1.  If this option is set, C<--tls-cert> is also required. (Arg-Required)

=item --tls-get-peer-cert [<output-file>]

Get a copy of the TLS peer's certificate.  If no argument is given, it will be displayed to C<STDOUT>.  If an argument is given it is assumed to be a filesystem path specifying where the certificate should be written.  The saved certificate can then be examined using standard tools such as the openssl command.  If a file is specified its contents will be overwritten. (Arg-Optional)

=item --tls-sni <sni-string>

Specify the Server Name Indication field to send when the TLS connection is initiated. (Arg-Required)

=back

=head1 AUTHENTICATION

Swaks will attempt to authenticate to the target mail server if instructed to do so.  This section details available authentication types, requirements, options and their interactions, and other fine points in authentication usage.  Because authentication is defined as an extension in the ESMTP protocol it will be unavailable if C<--protocol> is set to a variation of SMTP.

All authentication methods require base64 encoding.  If the L<MIME::Base64> Perl module is loadable Swaks attempts to use it to perform these encodings.  If L<MIME::Base64> is not available Swaks will use its own onboard base64 routines.  These are slower than the L<MIME::Base64> routines and less reviewed, though they have been tested thoroughly.  Using the L<MIME::Base64> module is encouraged.

If authentication is required (see options below for when it is and isn't required) and the requirements aren't met for the authentication type available, Swaks displays an error and exits.  Two ways this can happen include forcing Swaks to use a specific authentication type that Swaks can't use due to missing requirements, or allowing Swaks to use any authentication type, but the server only advertises types Swaks can't support.  In the former case Swaks errors out at option processing time since it knows up front it won't be able to authenticate.  In the latter case Swaks will error out at the authentication stage of the SMTP transaction since Swaks will not be aware that it will not be able to authenticate until that point.

Following are the supported authentication types including any individual notes and requirements.

The following options affect Swaks' use of authentication.  These options are all inter-related.  For instance, specifying C<--auth-user> implies C<--auth> and C<--auth-password>.  Specifying C<--auth-optional> implies C<--auth-user> and C<--auth-password>, etc.

=over 4

=item -a, --auth [<auth-type>[,<auth-type>[,...]]]

Require Swaks to authenticate.  If no argument is given, any supported auth-types advertised by the server are tried until one succeeds or all fail.  If one or more auth-types are specified as an argument, each that the server also supports is tried in order until one succeeds or all fail.  This option requires Swaks to authenticate, so if no common auth-types are found or no credentials succeed, Swaks displays an error and exits. (Arg-Optional)

The following tables lists the valid auth-types

=over 4

=item LOGIN, PLAIN

These basic authentication types are fully supported and tested and have no additional requirements

=item CRAM-MD5

The CRAM-MD5 authenticator requires the L<Digest::MD5> module.  It is fully tested and believed to work against any server that implements it.

=item DIGEST-MD5

The DIGEST-MD5 authenticator (RFC2831) requires the Authen::SASL module.  Version 20100211.0 and earlier used L<Authen::DigestMD5> which had some protocol level errors which prevented it from working with some servers.  L<Authen::SASL>'s DIGEST-MD5 handling is much more robust.

The DIGEST-MD5 implementation in Swaks is fairly immature.  It currently supports only the "auth" qop type, for instance.  If you have DIGEST-MD5 experience and would like to help Swaks support DIGEST-MD5 better, please get in touch with me.

The DIGEST-MD5 protocol's "realm" value can be set using the C<--auth-extra> "realm" keyword.  If no realm is given, a reasonable default will be used.

The DIGEST-MD5 protocol's "digest-uri" values can be set using the C<--auth-extra> option.  For instance, you could create the digest-uri-value of "lmtp/mail.example.com/example.com" with the option C<--auth-extra dmd5-serv-type=lmtp,dmd5-host=mail.example.com,dmd5-serv-name=example.com>.  The "digest-uri-value" string and its components is defined in RFC2831.  If none of these values are given, reasonable defaults will be used.

=item CRAM-SHA1

The CRAM-SHA1 authenticator requires the L<Digest::SHA> module.  This type has only been tested against a non-standard implementation on an Exim server and may therefore have some implementation deficiencies.

=item NTLM/SPA/MSN

These authenticators require the Authen::NTLM module.  Note that there are two modules using the L<Authen::NTLM> namespace on CPAN.  The Mark Bush implementation (Authen/NTLM-1.03.tar.gz) is the version required by Swaks.  This type has been tested against Exim, Communigate, and Exchange 2007.

In addition to the standard username and password, this authentication type can also recognize a "domain".  The domain can be set using the C<--auth-extra> "domain" keyword.  Note that this has never been tested with a mail server that doesn't ignore DOMAIN so this may be implemented incorrectly.

=back

=item -ao, --auth-optional [<auth-type>[,<auth-type>[,...]]]

This option behaves identically to C<--auth> except that it requests authentication rather than requiring it.  If no common auth-types are found or no credentials succeed, Swaks proceeds as if authentication had not been requested. (Arg-Optional)

=item -aos, --auth-optional-strict [<auth-type>[,<auth-type>[,...]]]

This option is a compromise between C<--auth> and C<--auth-optional>.  If no common auth-types are found, Swaks behaves as if C<--auth-optional> were specified and proceeds with the transaction.  If Swaks can't support requested auth-type, the server doesn't advertise any common auth-types, or if no credentials succeed, Swaks behaves as if C<--auth> were used and exits with an error. (Arg-Optional)

=item -au, --auth-user [<username>]

Provide the username to be used for authentication.  If no username is provided, indicate that Swaks should attempt to find the username via F<.netrc> (requires the L<Net::Netrc> module).  If no username is provided and cannot be found via F<.netrc>,  the user will be prompted to provide one.  The string C<< <> >> can be supplied to mean an empty username. (Arg-Required, From-Prompt)

=item -ap, --auth-password [<password>]

Provide the password to be used for authentication. If no password is provided, indicate that Swaks should attempt to find the password via F<.netrc> (requires the L<Net::Netrc> module).  If no password is provided and cannot be found via F<.netrc>,  the user will be prompted to provide one.  The string C<< <> >> can be supplied to mean an empty password. (Arg-Required, From-Prompt, Sensitive)

=item -ae, --auth-extra <key-value-pair>[,<key-value-pair>[,...]]

Some of the authentication types allow extra information to be included in the authentication process.  Rather than add a new option for every nook and cranny of each authenticator, the C<--auth-extra> option allows this information to be supplied.  The format for <key-value-pair> is KEYWORD=VALUE. (Arg-Required)

The following table lists the currently recognized keywords and the authenticators that use them

=over 4

=item realm, domain

The realm and domain keywords are synonymous.  Using either will set the "domain" option in NTLM/MSN/SPA and the "realm" option in DIGEST-MD5

=item dmd5-serv-type

The dmd5-serv-type keyword is used by the DIGEST-MD5 authenticator and is used, in part, to build the digest-uri-value string (see RFC2831)

=item dmd5-host

The dmd5-host keyword is used by the DIGEST-MD5 authenticator and is used, in part, to build the digest-uri-value string (see RFC2831)

=item dmd5-serv-name

The dmd5-serv-name keyword is used by the DIGEST-MD5 authenticator and is used, in part, to build the digest-uri-value string (see RFC2831)

=back

=item -am, --auth-map <key-value-pair>[,<key-value-pair>[,...]]

Provides a way to map alternate names onto base authentication types.  Useful for any sites that use alternate names for common types.  The format for <key-value-pair> is AUTH-ALIAS=AUTH-TYPE.  This functionality is actually used internally to map types SPA and MSN onto the base type NTLM.  The command line argument to simulate this would be C<--auth-map SPA=NTLM,MSN=NTLM>.  All of the auth-types listed above are valid targets for mapping except SPA and MSN. (Arg-Required)

=item -apt, --auth-plaintext

Instead of showing AUTH strings base64 encoded as they are transmitted, translate them to plaintext before printing on screen. (Arg-None)

=item -ahp, --auth-hide-password [<replacement-string>]

If this option is specified, any time a readable password would be printed to the terminal (specifically AUTH PLAIN and AUTH LOGIN) the password is replaced with the string 'PROVIDED_BUT_REMOVED' (or the contents of <replacement-string> if provided).  The dummy string may or may not be base64 encoded, contingent on the C<--auth-plaintext> option.

Note that C<--auth-hide-password> is similar, but not identical, to the C<--protect-prompt> option.  The former protects passwords from being displayed in the SMTP transaction regardless of how they are entered.  The latter protects sensitive strings when the user types them at the terminal, regardless of how the string would be used. (Arg-Optional)

=back

=head1 XCLIENT OPTIONS

XCLIENT is an SMTP extension introduced by the Postfix project.  XCLIENT allows a (properly-authorized) client to tell a server to use alternate information, such as IP address or hostname, for the client.  This allows much easier paths for testing mail server configurations.  Full details on the protocol are available at L<http://www.postfix.org/XCLIENT_README.html>.

The XCLIENT verb can be passed to the server multiple times per SMTP session with different attributes.  For instance, HELO and PROTO might be passed in one call and NAME and ADDR passed in a second. Because it can be useful for testing, Swaks exposes some control over how the attributes are grouped and in what order they are passed to the server. The different options attempt to expose simplicity for those using Swaks as a client, and complexity for those using Swaks to test installs.

=over 4

=item --xclient-addr [<string>]

=item --xclient-name [<string>]

=item --xclient-port [<string>]

=item --xclient-proto [<string>]

=item --xclient-destaddr [<string>]

=item --xclient-destport [<string>]

=item --xclient-helo [<string>]

=item --xclient-login [<string>]

=item --xclient-reverse-name [<string>]

These options specify XCLIENT attributes that should be sent to the target server.  If <string> is not provided, Swaks will prompt and read the value on C<STDIN>.  See L<http://www.postfix.org/XCLIENT_README.html> for official documentation for what the attributes mean and their possible values, including the special "[UNAVAILABLE]" and "[TEMPUNAVAIL]" values.

By way of simple example, setting C<--xclient-name foo.example.com --xclient-addr 192.168.1.1> will cause Swaks to send the SMTP command C<XCLIENT NAME=foo.example.com ADDR=192.168.1.1>.

Note that the "REVERSE_NAME" attribute doesn't seem to appear in the official documentation.  There is a mailing list thread that documents it, viewable at L<http://comments.gmane.org/gmane.mail.postfix.user/192623>.

These options can all be mixed with each other, and can be mixed with the C<--xclient> option (see below). By default all attributes will be combined into one XCLIENT call, but see C<--xclient-delim>. (Arg-Required, From-Prompt)

=item --xclient-delim

When this option is specified, it indicates a break in XCLIENT attributes to be sent.  For instance, setting C<--xclient-helo 'helo string' --xclient-delim --xclient-name foo.example.com --xclient-addr 192.168.1.1> will cause Swaks to send two XCLIENT calls, C<XCLIENT HELO=helo+20string> and C<XCLIENT NAME=foo.example.com ADDR=192.168.1.1>.  This option is ignored where it doesn't make sense (at the start or end of XCLIENT options, by itself, consecutively, etc). (Arg-None)

=item --xclient [<string>]

This is the "free form" XCLIENT option.  Whatever value is provided for <string> will be sent verbatim as the argument to the XCLIENT SMTP command.  For example, if C<--xclient 'NAME= ADDR=192.168.1.1 FOO=bar'> is used, Swaks will send the SMTP command C<XCLIENT NAME= ADDR=192.168.1.1 FOO=bar>.  If no argument is passed on command line, Swaks will prompt and read the value on STDIN.

The primary advantage to this over the more specific options above is that there is no XCLIENT syntax validation here.  This allows you to send invalid XCLIENT to the target server for testing.  Additionally, at least one MTA (Message Systems' Momentum, formerly ecelerity) implements XCLIENT without advertising supported attributes.  The C<--xclient> option allows you to skip the "supported attributes" check when communicating with this type of MTA (though see also C<--xclient-no-verify>).

The C<--xclient> option can be mixed freely with the C<--xclient-*> options above.  The argument to C<--xclient> will be sent in its own command group.  For instance, if C<--xclient-addr 192.168.0.1 --xclient-port 26 --xclient 'FOO=bar NAME=wind'> is given to Swaks, C<XCLIENT ADDR=192.168.0.1 PORT=26> and C<XCLIENT FOO=bar NAME=wind> will both be sent to the target server. (Arg-Required, From-Prompt)

=item --xclient-no-verify

Do not enforce the requirement that an XCLIENT attribute must be advertised by the server in order for Swaks to send it in an XCLIENT command.  This is to support servers which don't advertise the attributes but still support them. (Arg-None)

=item --xclient-before-starttls

If Swaks is configured to attempt both XCLIENT and STARTTLS, it will do STARTTLS first.  If this option is specified it will attempt XCLIENT first. (Arg-None)

=item --xclient-optional

=item --xclient-optional-strict

In normal operation, setting one of the C<--xclient*> options will require a successful XCLIENT transaction to take place in order to proceed (that is, XCLIENT needs to be advertised, all the user-requested attributes need to have been advertised, and the server needs to have accepted Swaks' XCLIENT request).  These options change that behavior.  C<--xclient-optional> tells Swaks to proceed unconditionally past the XCLIENT stage of the SMTP transaction, regardless of whether it was successful.  C<--xclient-optional-strict> is similar but more granular.  The strict version will continue to XCLIENT was not advertised, but will fail if XCLIENT was attempted but did not succeed. (Arg-None)

=back

=head1 PROXY OPTIONS

Swaks implements the Proxy protocol as defined in L<http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt>.  Proxy allows an application load balancer, such as HAProxy, to be used in front of an MTA while still allowing the MTA access to the originating host information.  Proxy support in Swaks allows direct testing of an MTA configured to expect requests from a proxy, bypassing the proxy itself during testing.

Swaks makes no effort to ensure that the Proxy options used are internally consistent.  For instance, C<--proxy-family> (in version 1) is expected to be one of "TCP4" or "TCP6".  While it will likely not make sense to the target server, Swaks makes no attempt to ensure that C<--proxy-source> and C<--proxy-dest> are in the same protocol family as C<--proxy-family> or each other.

The C<--proxy> option is mutually exclusive with all other C<--proxy-*> options except C<--proxy-version>.

When C<--proxy> is not used, all of C<--proxy-family>, C<--proxy-source>, C<--proxy-source-port>, C<--proxy-dest>, and C<--proxy-dest-port> are required.  Additionally, when C<--proxy-version> is 2, C<--proxy-protocol> and C<--proxy-command> are optional.

=over 4

=item --proxy-version [ 1 | 2 ]

Whether to use version 1 (human readable) or version 2 (binary) of the Proxy protocol.  Version 1 is the default.  Version 2 is only implemented through the "address block", and is roughly on par with the information provided in version 1.

=item --proxy [<string>]

If this option is used, its argument is passed unchanged after the "PROXY " portion (or the 12-byte protocol header for version 2) of the Proxy exchange.  This option allows sending incomplete or malformed Proxy strings to a target server for testing.  No attempt to translate or modify this string is made, so if used with C<--proxy-version 2> the argument should be in the appropriate binary format.  This option is mutually exclusive with all other C<--proxy-*> options which provide granular proxy information. (Arg-Required, From-Prompt)

=item --proxy-family [<string>]

For version 1, specifies both the address family and transport protocol.  The protocol defines TCP4 and TCP6.

For version 2, specifies only the address family.  The protocol defines AF_UNSPEC, AF_INET, AF_INET6, and AF_UNIX. (Arg-Required, From-Prompt)

=item --proxy-protocol [<string>]

For version 2, specifies the transport protocol.  The protocol defines UNSPEC, STREAM, and DGRAM.  The default is STREAM.  This option is unused in version 1. (Arg-Required, From-Prompt)

=item --proxy-command [<string>]

For version 2, specifies the transport protocol.  The protocol defines LOCAL and PROXY.  The default is PROXY.  This option is unused in version 1. (Arg-Required, From-Prompt)

=item --proxy-source [<string>]

Specify the source address of the proxied connection. (Arg-Required, From-Prompt)

=item --proxy-source-port [<string>]

Specify the source port of the proxied connection. (Arg-Required, From-Prompt)

=item --proxy-dest [<string>]

Specify the destination address of the proxied connection. (Arg-Required, From-Prompt)

=item --proxy-dest-port [<string>]

Specify the destination port of the proxied connection. (Arg-Required, From-Prompt)

=back

=head1 DATA OPTIONS

These options pertain to the contents for the DATA portion of the SMTP transaction.  By default a very simple message is sent.  If the C<--attach> or C<--attach-body> options are used, Swaks attempts to upgrade to a MIME message.

=over 4

=item -d, --data [<data-portion>]

Use argument as the entire contents of DATA.

If no argument is provided, user will be prompted to supply value.

If the argument C<-> is provided the data will be read from C<STDIN> with no prompt.

If the argument starts with C<@> it will be treated as a filename.  If you would like to pass in an argument that starts with C<@> and isn't a filename, prefix the argument with an additional C<@>.  For example, C<@file.txt> will force processing of F<file.txt>.  C<@@data> will use the string '@data'.

If the argument does not contain any literal (0x0a) or representative (0x5c, 0x6e or %NEWLINE%) newline characters, it will be treated as a filename.  If the file is open-able, the contents of the file will be used as the data portion.  If the file cannot be opened, Swaks will error and exit.  The entire behavior described in this paragraph is deprecated and will be removed in a future release.  Instead use a leading C<@> to explicitly set that the argument is a filename.

Any other argument will be used as the DATA contents.

The value can be on one single line, with C<\n> (ASCII 0x5c, 0x6e) representing where line breaks should be placed.  Leading dots will be quoted.  Closing dot is not required but is allowed.  The default value for this option is C<Date: %DATE%\nTo: %TO_ADDRESS%\nFrom: %FROM_ADDRESS%\nSubject: test %DATE%\nMessage-Id: <%MESSAGEID%>\nX-Mailer: swaks v%SWAKS_VERSION% jetmore.org/john/code/swaks/\n%NEW_HEADERS%\n%BODY%\n>.

Very basic token parsing is performed on the DATA portion.  The following table shows the recognized tokens and their replacement values. (Arg-Required, From-Prompt, From-File)

=over 4

=item %FROM_ADDRESS%

Replaced with the envelope-sender.

=item %TO_ADDRESS%

Replaced with the envelope-recipient(s).

=item %DATE%

Replaced with the current time in a format suitable for inclusion in the Date: header.  Note this attempts to use the standard module L<POSIX> for timezone calculations.  If this module is unavailable the date string will be in GMT.

=item %MESSAGEID%

Replaced with a message ID string suitable for use in a Message-Id header.  The value for this token will remain consistent for the life of the process.

=item %SWAKS_VERSION%

Replaced with the version of the currently-running Swaks process.

=item %NEW_HEADERS%

Replaced with the contents of the C<--add-header> option.  If C<--add-header> is not specified this token is simply removed.

=item %BODY%

Replaced with the value specified by the C<--body> option.  See C<--body> for default.

=item %NEWLINE%

Replaced with carriage return, newline (0x0d, 0x0a).  This is identical to using C<\n> (0x5c, 0x6e), but doesn't have the escaping concerns that the backslash can cause on the newline.

=back

=item -dab, --dump-as-body [<section>[,<section>[,...]]]

If C<--dump-as-body> is used and no other option is used to change the default body of the message, the body is replaced with output similar to the output of what is provided by C<--dump>.  C<--dump>'s initial program capability stanza is not displayed, and the "data" section is not included.  Additionally, C<--dump> always includes passwords.  By default C<--dump-as-body> does not include passwords, though this can be changed with C<--dump-as-body-shows-password>.  C<--dump-as-body> takes the same arguments as C<--dump> except the SUPPORT and DATA arguments are not supported. (Arg-Optional)

=item -dabsp, --dump-as-body-shows-password

Cause C<--dump-as-body> to include plaintext passwords.  This option is not recommended.  This option implies C<--dump-as-body>. (Arg-None)

=item --body [<body-specification>]

Specify the body of the email.  The default is "This is a test mailing".  If no argument to C<--body> is given, prompt to supply one interactively.  If C<-> is supplied, the body will be read from standard input.  Arguments beginning with C<@> will be treated as filenames containing the body data to use (see C<--data> for more detail).

If, after the above processing, the argument represents an open-able file, the content of that file is used as the body.  This is deprecated behavior and will be removed in a future release.  Instead use a leading C<@> to explicitly set that the argument is a filename.

If the message is forced to MIME format (see C<--attach>) C<--body 'body text'> is the same as C<--attach-type text/plain --attach-body 'body text'>.  See C<--attach-body> for details on creating a multipart/alternative body. (Arg-Required, From-Prompt, From-File)

=item --attach [<attachment-specification>]

When one or more C<--attach> option is supplied, the message is changed into a multipart/mixed MIME message.  The arguments to C<--attach> are processed the same as C<--body> with respect to C<STDIN>, file contents, etc.  C<--attach> can be supplied multiple times to create multiple attachments.  By default, each attachment is attached as an application/octet-stream file.  See C<--attach-type> for changing this behavior.

If the contents of the attachment are provided via a file name, the MIME encoding will include that file name.  See C<--attach-name> for more detail on file naming.

It is legal for C<-> (C<STDIN>) to be specified as an argument multiple times (once for C<--body> and multiple times for C<--attach>).  In this case, the same content will be attached each time it is specified.  This is useful for attaching the same content with multiple MIME types. (Arg-Required, From-File)

=item --attach-body [<body-specification>]

This is a variation on C<--attach> that is specifically for the body part of the email.  It behaves identically to C<--attach> in that it takes the same arguments and forces the creation of a MIME message.  However, it is different in that the argument will always be the first MIME part in the message, no matter where in option processing order it is encountered.  Additionally, C<--attach-body> options stack to allow creation of multipart/alternative bodies.  For example, C<--attach-type text/plain --attach-body 'plain text body' --attach-type text/html --attach-body 'html body'> would create a multipart/alternative message body. (Arg-Required, From-File)

=item --attach-type <mime-type>

By default, content that gets MIME attached to a message with the C<--attach> option is encoded as application/octet-stream (except for the body, which is text/plain by default).  C<--attach-type> changes the mime type for every C<--attach> option which follows it.  It can be specified multiple times.  The current MIME type gets reset to application/octet-stream between processing body parts and other parts. (Arg-Required)

=item --attach-name [<name>]

This option sets the filename that will be included in the MIME part created for the next C<--attach> option.  If no argument is set for this option, it causes no filename information to be included for the next MIME part, even if Swaks could generate it from the local file name. (Arg-Optional)

=item -ah, --add-header <header>

This option allows headers to be added to the DATA.  If C<%NEW_HEADERS%> is present in the DATA it is replaced with the argument to this option.  If C<%NEW_HEADERS%> is not present, the argument is inserted between the first two consecutive newlines in the DATA (that is, it is inserted at the end of the existing headers).

The option can either be specified multiple times or a single time with multiple headers separated by a literal C<\n> string.  So, C<--add-header 'Foo: bar' --add-header 'Baz: foo'" and "--add-header 'Foo: bar\nBaz: foo'> end up adding the same two headers. (Arg-Required)

=item --header <header-and-data>, --h-<header> <data>

These options allow a way to change headers that already exist in the DATA.  C<--header 'Subject: foo'> and C<--h-Subject foo> are equivalent.  If the header does not already exist in the data then this argument behaves identically to C<--add-header>.  However, if the header already exists it is replaced with the one specified.  Negating the version of this option with the header name in the option (eg C<--no-header-Subject>) will remove all previously processed C<--header> options, not just the ones used for 'Subject'. (Arg-Required)

=item -g

This option is a direct alias to C<--data -> (read DATA from C<STDIN>).  It is totally secondary to C<--data>.  Any occurrence of C<--data> will cause C<-g> to be ignored.  This option cannot be negated with the C<no-> prefix.  This option is deprecated and will be removed in a future version of Swaks. (Arg-None, Deprecated)

=item --no-data-fixup, -ndf

This option forces Swaks to do no massaging of the DATA portion of the email.  This includes token replacement, From_ stripping, trailing-dot addition, C<--body>/attachment inclusion, and any header additions.  This option is only useful when used with C<--data>, since the internal default DATA portion uses tokens. (Arg-None)

=item --no-strip-from, -nsf

Don't strip the From_ line from the DATA portion, if present. (Arg-None)

=back

=head1 OUTPUT OPTIONS

Swaks provides a transcript of its transactions to its caller (C<STDOUT>/C<STDERR>) by default.  This transcript aims to be as faithful a representation as possible of the transaction though it does modify this output by adding informational prefixes to lines and by providing plaintext versions of TLS transactions

The "informational prefixes" are referred to as transaction hints.  These hints are initially composed of those marking lines that are output of Swaks itself, either informational or error messages, and those that indicate a line of data actually sent or received in a transaction.  This table indicates the hints and their meanings:

=over 4

=item C<===>

Indicates an informational line generated by Swaks.

=item C<***>

Indicates an error generated within Swaks.

=item C<S< >-E<gt>>

Indicates an expected line sent by Swaks to target server.

=item C<S< >~E<gt>>

Indicates a TLS-encrypted, expected line sent by Swaks to target server.

=item C<**E<gt>>

Indicates an unexpected line sent by Swaks to the target server.

=item C<*~E<gt>>

Indicates a TLS-encrypted, unexpected line sent by Swaks to target server.

=item C<S<  >E<gt>>

Indicates a raw chunk of text sent by Swaks to a target server (see C<--show-raw-text>).  There is no concept of "expected" or "unexpected" at this level.

=item C<E<lt>-S< >>

Indicates an expected line sent by target server to Swaks.

=item C<E<lt>~S< >>

Indicates a TLS-encrypted, expected line sent by target server to Swaks.

=item C<E<lt>**>

Indicates an unexpected line sent by target server to Swaks.

=item C<E<lt>~*>

Indicates a TLS-encrypted, unexpected line sent by target server to Swaks.

=item C<E<lt>S<  >>

Indicates a raw chunk of text received by Swaks from a target server (see C<--show-raw-text>).  There is no concept of "expected" or "unexpected" at this level.

=back

The following options control what and how output is displayed to the caller.

=over 4

=item -n, --suppress-data

Summarizes the DATA portion of the SMTP transaction instead of printing every line.  This option is very helpful, bordering on required, when using Swaks to send certain test emails.  Emails with attachments, for instance, will quickly overwhelm a terminal if the DATA is not suppressed. (Arg-None)

=item -stl, --show-time-lapse [i]

Display time lapse between send/receive pairs.  This option is most useful when L<Time::HiRes> is available, in which case the time lapse will be displayed in thousandths of a second.  If L<Time::HiRes> is unavailable or "i" is given as an argument the lapse will be displayed in integer seconds only. (Arg-Optional)

=item -nih, --no-info-hints

Don't display the transaction hint for informational transactions.  This is most useful when needing to copy some portion of the informational lines, for instance the certificate output from C<--tls-get-peer-cert>. (Arg-None)

=item -nsh, --no-send-hints

=item -nrh, --no-receive-hints

=item -nth, --no-hints

C<--no-send-hints> and C<--no-receive-hints> suppress the transaction hints from send and receive lines, respectively.  This is often useful when copying some portion of the transaction for use elsewhere (for instance, C<--no-send-hints --hide-receive --hide-informational> is a useful way to get only the client-side commands for a given transaction).  C<--no-hints> is identical to specifying both C<--no-send-hints> and C<--no-receive-hints>. (Arg-None)

=item -raw, --show-raw-text

This option will print a hex dump of raw data sent and received by Swaks.  Each hex dump is the contents of a single read or write on the network.  This should be identical to what is already being displayed (with the exception of the C<\r> characters being removed).  This option is useful in seeing details when servers are sending lots of data in single packets, or breaking up individual lines into multiple packets.  If you really need to go in depth in that area you're probably better with a packet sniffer, but this option is a good first step to seeing odd connection issues. (Arg-None)

=item --output, --output-file <file-path>

=item --output-file-stdout <file-path>

=item --output-file-stderr <file-path>

These options allow the user to send output to files instead of C<STDOUT>/C<STDERR>.  The first option sends both to the same file.  The arguments of C<&STDOUT> and C<&STDERR> are treated specially, referring to the "normal" file handles, so C<--output-file-stderr '&STDOUT'> would redirect C<STDERR> to C<STDOUT>.  These options are honored for all output except C<--help> and C<--version>. (Arg-Required)

=item -pp, --protect-prompt

Don't echo user input on prompts that are potentially sensitive (right now only authentication password).  Very specifically, any option which is marked 'Sensitive' and eventually prompts for an argument will do its best to mask that argument from being echoed.  See also C<--auth-hide-password>. (Arg-None)

=item -hr, --hide-receive

Don't display lines sent from the remote server being received by Swaks. (Arg-None)

=item -hs, --hide-send

Don't display lines being sent by Swaks to the remote server. (Arg-None)

=item -hi, --hide-informational

Don't display non-error informational lines from Swaks itself. (Arg-None)

=item -ha, --hide-all

Do not display any content to the terminal. (Arg-None)

=item -S, --silent [ 1 | 2 | 3 ]

Cause Swaks to be silent.  If no argument is given or if an argument of "1" is given, print no output unless/until an error occurs, after which all output is shown.  If an argument of "2" is given, only print errors.  If "3" is given, show no output ever.  C<--silent> affects most output but not all.  For instance, C<--help>, C<--version>, C<--dump>, and C<--dump-mail> are not affected. (Arg-Optional)

=item --support

Print capabilities and exit.  Certain features require non-standard Perl modules.  This option evaluates whether these modules are present and displays which functionality is available and which isn't, and which modules would need to be added to gain the missing functionality. (Arg-None)

=item --dump-mail

Cause Swaks to process all options to generate the message it would send, then print that message to C<STDOUT> instead of sending it.  This output is identical to the "data" section of C<--dump>, except without the trailing dot. (Arg-None)

=item --dump [<section>[,<section>[,...]]]

This option causes Swaks to print the results of option processing, immediately before mail would have been sent.  No mail will be sent when C<--dump> is used.  Note that C<--dump> is a pure self-diagnosis tool and no effort is made or will ever be made to mask passwords in the C<--dump> output. If a section is provided as an argument to this option, only the requested section will be shown.  Currently supported arguments are SUPPORT, APP, OUTPUT, TRANSPORT, PROTOCOL, XCLIENT, PROXY, TLS, AUTH, DATA, and ALL.  If no argument is provided, all sections are displayed (Arg-Optional)

=item --help

Display this help information and exit. (Arg-None)

=item --version

Display version information and exit. (Arg-None)

=back

=head1 DEPRECATIONS

The following features are deprecated and will be removed in a future version of Swaks

=over 4

=item -g option

Will be removed no sooner than November 1, 2021.

The -g option is currently a less-good alias to C<--data ->.  Any uses of C<-g> should be able to be directly migrated to C<--data -> instead.

=item auto-filename detection

Will be removed no sooner than November 1, 2021.

The C<--data>, C<--body>, C<--attach>, and C<--attach-body> options currently will attempt to distinguish between an argument that is the actual value to use vs. an argument that represents a file containing the data to use.  This behavior has been superseded by prefixing an argument to these options with C<@> to explicitly indicate that the argument indicates a file.  Any uses of providing a filename to one of these options should be moved to using C<@> to indicate a filename is being used.

=back

=head1 PORTABILITY

=over 4

=item OPERATING SYSTEMS

This program was primarily intended for use on UNIX-like operating systems, and it should work on any reasonable version thereof.  It has been developed and tested on Solaris, Linux, and Mac OS X and is feature complete on all of these.

This program is known to demonstrate basic functionality on Windows using ActiveState's Perl.  It has not been fully tested.  Known to work are basic SMTP functionality and the LOGIN, PLAIN, and CRAM-MD5 auth types.  Unknown is any TLS functionality and the NTLM/SPA and DIGEST-MD5 auth types.

Because this program should work anywhere Perl works, I would appreciate knowing about any new operating systems you've thoroughly used Swaks on as well as any problems encountered on a new OS.

=item MAIL SERVERS

This program was almost exclusively developed against Exim mail servers.  It has been used casually by the author, though not thoroughly tested, with Sendmail, Smail, Exchange, Oracle Collaboration Suite, qpsmtpd, and Communigate.  Because all functionality in Swaks is based on known standards it should work with any fairly modern mail server.  If a problem is found, please alert the author at the address below.

=back

=head1 ENVIRONMENT VARIABLES

=over 4

=item LOGNAME

If Swaks must create a sender address, C<$LOGNAME> is used as the message local-part if it is set, and unless C<--force-getpwuid> is used.

=item SWAKS_HOME

Used when searching for a F<.swaksrc> configuration file.  See OPTION PROCESSING -> L</"CONFIGURATION FILES"> above.

=item SWAKS_OPT_*

Environment variable prefix used to specify Swaks options from environment variables.  See OPTION PROCESSING -> L</"CONFIGURATION ENVIRONMENT VARIABLES"> above.

=back

=head1 EXIT CODES

=over 4

=item Z<>0

no errors occurred

=item Z<>1

error parsing command line options

=item Z<>2

error connecting to remote server

=item Z<>3

unknown connection type

=item Z<>4

while running with connection type of "pipe", fatal problem writing to or reading from the child process

=item Z<>5

while running with connection type of "pipe", child process died unexpectedly.  This can mean that the program specified with C<--pipe> doesn't exist.

=item Z<>6

Connection closed unexpectedly.  If the close is detected in response to the 'QUIT' Swaks sends following an unexpected response, the error code for that unexpected response is used instead.  For instance, if a mail server returns a 550 response to a MAIL FROM: and then immediately closes the connection, Swaks detects that the connection is closed, but uses the more specific exit code 23 to detail the nature of the failure.  If instead the server return a 250 code and then immediately closes the connection, Swaks will use the exit code 6 because there is not a more specific exit code.

=item Z<>10

error in prerequisites (needed module not available)

=item Z<>21

error reading initial banner from server

=item Z<>22

error in HELO transaction

=item Z<>23

error in MAIL transaction

=item Z<>24

no RCPTs accepted

=item Z<>25

server returned error to DATA request

=item Z<>26

server did not accept mail following data

=item Z<>27

server returned error after normal-session quit request

=item Z<>28

error in AUTH transaction

=item Z<>29

error in TLS transaction

=item Z<>30

PRDR requested/required but not advertised

=item Z<>32

error in EHLO following TLS negotiation

=item Z<>33

error in XCLIENT transaction

=item Z<>34

error in EHLO following XCLIENT

=item Z<>35

error in PROXY option processing

=item Z<>36

error sending PROXY banner

=back

=head1 ABOUT THE NAME

The name "Swaks" is a (sort-of) acronym for "SWiss Army Knife SMTP".  It was chosen to be fairly distinct and pronounceable.  While "Swaks" is unique as the name of a software package, it has some other, non-software meanings.  Please send in other uses of "swak" or "swaks" for inclusion.

=over 4

=item "Sealed With A Kiss"

SWAK/SWAKs turns up occasionally on the internet with the meaning "with love".

=item bad / poor / ill (Afrikaans)

Seen in the headline "SA se bes en swaks gekledes in 2011", which was translated as "best and worst dressed" by native speakers.  Google Translate doesn't like "swaks gekledes", but it will translate "swak" as "poor" and "swak geklede" as "ill-dressed".

=back

=head1 LICENSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

=head1 CONTACT INFORMATION

General contact, questions, patches, requests, etc to proj-swaks@jetmore.net.

Change logs, this help, and the latest version are found at L<http://www.jetmore.org/john/code/swaks/>.

Swaks is crafted with love by John Jetmore from the cornfields of Indiana, United States of America.

=head1 NOTIFICATIONS

=over 4

=item Email

updates-swaks@jetmore.net

If you would like to be put on a list to receive notifications when a new version of Swaks is released, please send an email to this address.  There will not be a response to your email.

=item Website

L<http://www.jetmore.org/john/blog/c/swaks/>

=item RSS Feed

L<http://www.jetmore.org/john/blog/c/swaks/feed/>

=item Twitter

<http://twitter.com/SwaksSMTP>

=back

=cut
__END__

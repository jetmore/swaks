#!/usr/bin/perl

# use 'swaks --help' to view documentation for this program
# if you want to be notified about future releases of this program,
#	please send an email to updates-swaks@jetmore.net

use strict;

my($p_name)   = $0 =~ m|/?([^/]+)$|;
my $p_version = "20061116.0";
my $p_usage   = "Usage: $p_name [--help|--version] (see --help for details)";
my $p_cp      = <<EOM;
        Copyright (c) 2003-2006 John Jetmore <jj33\@pobox.com>

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
ext_usage(); # before we do anything else, check for --help

my %O        = ();
$|           = 1;

# need to rewrite header-HEADER opts before std option parsing
for (my $i = 0; $i < scalar(@ARGV); $i++) {
  if ($ARGV[$i] =~ /^--h(?:eader)?-(.*)$/) {
    $ARGV[$i] = "--header";  $ARGV[$i+1] = "$1: $ARGV[$i+1]";
  }
}
if (!load("Getopt::Long")) {
    ptrans(12, "Unable to load Getopt::Long for option processing, Exiting");
    exit(1);
}
Getopt::Long::Configure("bundling_override");
GetOptions(
  'l|input-file=s'  => \$O{option_file},   # (l)ocation of input data
  'f|from:s'        => \$O{mail_from},     # envelope-(f)rom address
  't|to:s'          => \$O{mail_to},       # envelope-(t)o address
  'h|helo|ehlo|lhlo:s' => \$O{mail_helo},  # (h)elo string
  's|server:s'      => \$O{mail_server},   # (s)erver to use
  'p|port:s'        => \$O{mail_port},     # (p)ort to use
  'protocol:s'      => \$O{mail_protocol}, # protocol to use (smtp, esmtp, lmtp)
  'd|data:s'        => \$O{mail_data},     # (d)ata portion ('\n' for newlines)
  'timeout:s'       => \$O{timeout},       # timeout for each trans (def 30s)
  'g'               => \$O{data_on_stdin}, # (g)et data on stdin
  'm'               => \$O{emulate_mail},  # emulate (M)ail command
  'q|quit|quit-after=s' => \$O{quit_after}, # (q)uit after
  'n|suppress-data' => \$O{suppress_data}, # do (n)ot print data portion
  'a|auth:s'        => \$O{auth},          # force auth, exit if not supported
  'au|auth-user:s'  => \$O{auth_user},     # user for auth
  'ap|auth-password:s' => \$O{auth_pass},  # pass for auth
  'am|auth-map=s'   => \$O{auth_map},      # auth type map
  #'ahp|auth-hide-password' => \$O{auth_hidepw}, # hide passwords when possible
  'apt|auth-plaintext' => \$O{auth_showpt}, # translate base64 strings
  'ao|auth-optional:s' => \$O{auth_optional}, # auth optional (ignore failure)
  'support'         => \$O{get_support},   # report capabilties
  'li|local-interface:s' => \$O{lint},     # local interface to use
  'tls'             => \$O{tls},           # use TLS
  'tlso|tls-optional' => \$O{tls_optional}, # use tls if available
  'tlsc|tls-on-connect' => \$O{tls_on_connect}, # use tls if available
  'S|silent+'       => \$O{silent},        # suppress output to varying degrees
  'nsf|no-strip-from' => \$O{no_strip_from}, # Don't strip From_ line from DATA
  'nth|no-hints'    => \$O{no_hints},      # Don't show transaction hints
  'hr|hide-receive' => \$O{hide_receive},  # Don't show reception lines
  'hs|hide-send'    => \$O{hide_send},     # Don't show sending lines
  'stl|show-time-lapse:s' => \$O{show_time_lapse}, # print lapse for send/recv
  'ndf|no-data-fixup' => \$O{no_data_fixup}, # don't touch the data
  'pipe:s'          => \$O{pipe_cmd},      # command to communicate with
  'socket:s'        => \$O{socket},        # unix domain socket to talk to
  'body:s'          => \$O{body_822},      # the content of the body of the DATA
  'attach-type|attach:s' => \@{$O{attach_822}}, # A file to attach
  'ah|add-header:s' => \@{$O{add_header}}, # replacement for %H DATA token
  'header:s'        => \@{$O{header}},     # replace header if exist, else add
  'dump'            => \$O{dump_args},     # build options and dump
  'pipeline'        => \$O{pipeline},      # attempt PIPELINING
  'force-getpwuid'  => \$O{force_getpwuid} # use getpwuid building -f
) || exit(1);

# lists of dependencies for features
%G::dependencies = (
  auth            => { name => "Basic AUTH",     opt => ['MIME::Base64'],
                       req  => [] },
  auth_cram_md5   => { name => "AUTH CRAM-MD5",  req => ['Digest::MD5'] },
  auth_cram_sha1  => { name => "AUTH CRAM-SHA1", req => ['Digest::SHA1'] },
  auth_ntlm       => { name => "AUTH NTLM",      req => ['Authen::NTLM'] },
  auth_digest_md5 => { name => "AUTH DIGEST-MD5",
                       req  => ['Authen::DigestMD5'] },
  dns             => { name => "MX Routing",     req => ['Net::DNS'] },
  tls             => { name => "TLS",            req => ['Net::SSLeay'] },
  pipe            => { name => "Pipe Transport", req => ['IPC::Open2'] },
  socket          => { name => "Socket Transport", req => ['IO::Socket'] },
  date_manip      => { name => "Date Manipulation", req => ['Time::Local'] },
  hostname        => { name => "Local Hostname Detection",
                       req  => ['Sys::Hostname'] },
  hires_timing    => { name => "High Resolution Timing",
                       req  => ['Time::HiRes'] },
);

if ($O{get_support}) {
  test_support();
  exit(0);
}

# We need to fix things up a bit and set a couple of global options
my $opts = process_args(\%O);

if ($G::dump_args) {
  test_support();
  print "dump_args        = ", $G::dump_args ? "TRUE" : "FALSE", "\n";
  print "server_only      = ", $G::server_only ? "TRUE" : "FALSE", "\n";
  print "show_time_lapse  = ", $G::show_time_lapse ? "TRUE" : "FALSE", "\n";
  print "show_time_hires  = ", $G::show_time_hires ? "TRUE" : "FALSE", "\n";
  print "auth_showpt      = ", $G::auth_showpt ? "TRUE" : "FALSE", "\n";
  print "suppress_data    = ", $G::suppress_data ? "TRUE" : "FALSE", "\n";
  print "no_hints         = ", $G::no_hints ? "TRUE" : "FALSE", "\n";
  print "hide_send        = ", $G::hide_send ? "TRUE" : "FALSE", "\n";
  print "hide_receive     = ", $G::hide_receive ? "TRUE" : "FALSE", "\n";
  print "pipeline         = ", $G::pipeline ? "TRUE" : "FALSE", "\n";
  print "silent           = $G::silent\n";
  print "protocol         = $G::protocol\n";
  print "type             = $G::link{type}\n";
  print "server           = $G::link{server}\n";
  print "sockfile         = $G::link{sockfile}\n";
  print "process          = $G::link{process}\n";
  print "from             = $opts->{from}\n";
  print "to               = $opts->{to}\n";
  print "helo             = $opts->{helo}\n";
  print "port             = $G::link{port}\n";
  print "tls              = ";
  if ($G::tls) {
    print "starttls (", $G::tls_optional ? 'optional' : 'required', ")\n";
  } elsif ($G::tls_on_connect) {
    print "on connect (required)\n";
  } else { print "no\n"; }
  print "auth             = ";
  if ($opts->{a_type}) {
    print $G::auth_optional ? 'optional' : 'yes', " type='",
          join(',', @{$opts->{a_type}}), "' ",
          "user='$opts->{a_user}' pass='$opts->{a_pass}'\n";
  } else { print "no\n"; }
  print "auth map         = ", join("\n".' 'x19,
                              map { "$_ = ".
                                    join(', ', @{$G::auth_map_t{$_}})
                                  } (keys %G::auth_map_t)
                             ), "\n";
  print "quit after       = $G::quit_after\n";
  print "local int        = $G::link{lint}\n";
  print "timeout          = $G::link{timeout}\n";
  print "data             = <<.\n$opts->{data}\n";
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
    ptrans(11, "Trying $G::link{server}:$G::link{port}...");
    $@ = "";
    $G::link{sock} = IO::Socket::INET->new(PeerAddr => $G::link{server},
                            PeerPort  => $G::link{port}, Proto => 'tcp',
                            Timeout   => $G::link{timeout},
                            LocalAddr => $G::link{lint});

    if ($@) {
      ptrans(12, "Error connecting $G::link{lint} " .
                            "to $G::link{server}:$G::link{port}:\n\t$@");
      exit(2);
    }
    ptrans(11, "Connected to $G::link{server}.");
  } elsif ($G::link{type} eq 'socket-unix') {
    ptrans(11, "Trying $G::link{sockfile}...");
    $SIG{PIPE} = 'IGNORE';
    $@ = "";
    $G::link{sock} = IO::Socket::UNIX->new(Peer => $G::link{sockfile},
                            Timeout   => $G::link{timeout});

    if ($@) {
      ptrans(12, "Error connecting to $G::link{sockfile}:\n\t$@");
      exit(2);
    }
    ptrans(11, "Connected to $G::link{sockfile}.");
  } elsif ($G::link{type} eq 'pipe') {
    $SIG{PIPE} = 'IGNORE';
    $SIG{CHLD} = 'IGNORE';
    ptrans(11, "Trying pipe to $G::link{process}...");
    eval{
      open2($G::link{sock}{re}, $G::link{sock}{wr}, $G::link{process});
    };
    if ($@) {
      ptrans(12, "Error connecting to $G::link{process}:\n\t$@");
      exit(2);
    }
    select((select($G::link{sock}{wr}), $| = 1)[0]);
    select((select($G::link{sock}{re}), $| = 1)[0]);
    ptrans(11, "Connected to $G::link{process}.");
  } else {
    ptrans(12, "Unknown or unimplemented connection type " .
                          "$G::link{type}");
    exit(3);
  }
}

sub sendmail {
  my $from    = shift;	# envelope-from
  my $to      = shift;	# envelope-to
  my $helo    = shift;	# who am I?
  my $data    = shift;	# body of message (content after DATA command)
  my $a_user  = shift;	# what user to auth with?
  my $a_pass  = shift;	# what pass to auth with
  my $a_type  = shift;	# what kind of auth (this must be set to to attempt)
  my $ehlo    = {};	# If server is esmtp, save advertised features here

  # start up tls if -tlsc specified
  if ($G::tls_on_connect) {
    if (start_tls()) {
      ptrans(11, "TLS started w/ cipher $G::link{tls}{cipher}");
    } else {
      ptrans(12, "TLS startup failed ($G::link{tls}{res})");
      exit(29);
    }
  }

  # read the server's 220 banner
  do_smtp_gen(undef, '220') || do_smtp_quit(1, 21);

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'connect');

  # Send a HELO string
  do_smtp_helo($helo, $ehlo, $G::protocol) || do_smtp_quit(1, 22);

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'first-helo');

  # handle TLS here if user has requested it
  if ($G::tls) {
    do_smtp_quit(1, 29) if (!do_smtp_tls($ehlo) && !$G::tls_optional);
  }

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'tls');

  #if ($G::link{tls}{active} && $ehlo->{STARTTLS}) {
  if ($G::link{tls}{active} && !$G::tls_on_connect) {
    # According to RFC3207, we need to forget state info and re-EHLO here
    $ehlo = {};
    do_smtp_helo($helo, $ehlo, $G::protocol) || do_smtp_quit(1, 32);
  }

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'helo');

  # handle auth here if user has requested it
  if ($a_type) {
    do_smtp_quit(1, 28) if (!do_smtp_auth($ehlo, $a_type, $a_user, $a_pass)
                            && !$G::auth_optional);
  }

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'auth');

  # send MAIL
  #do_smtp_gen("MAIL FROM:<$from>", '250') || do_smtp_quit(1, 23);
  do_smtp_mail($from); # failures in this handled by smtp_mail_callback

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'mail');

  # send RCPT (sub handles multiple, comma-delimited recips
  #do_smtp_rcpt($to) || do_smtp_quit(1, 24);
  do_smtp_rcpt($to); # failures in this handled by smtp_rcpt_callback
                     # note that smtp_rcpt_callback increments
                     # $G::smtp_rcpt_failures at every failure.  This and
                     # $G::smtp_rcpt_total are used after DATA for LMTP

  # QUIT here if the user has asked us to do so
  do_smtp_quit(1, 0) if ($G::quit_after eq 'rcpt');

  # send DATA
  do_smtp_gen('DATA', '354') || do_smtp_quit(1, 25);

  # send the actual data
  #do_smtp_gen($data, '250', undef, $G::suppress_data) || do_smtp_quit(1, 26);
  # this was moved to a custom sub because the server will have a custom
  # behaviour when using LMTP
  do_smtp_data($data, $G::suppress_data) || do_smtp_quit(1, 26);

  # send QUIT
  do_smtp_quit(0) || do_smtp_quit(1, 27);
}

sub start_tls {
  my %t         = (); # This is a convenience var to access $G::link{tls}{...}
  $G::link{tls} = \%t;

  Net::SSLeay::load_error_strings();
  Net::SSLeay::SSLeay_add_ssl_algorithms();
  Net::SSLeay::randomize();
  $t{con}    = Net::SSLeay::CTX_new() || return(0);
  Net::SSLeay::CTX_set_options($t{con}, &Net::SSLeay::OP_ALL); # error check
  $t{ssl}    = Net::SSLeay::new($t{con}) || return(0);
  if ($G::link{type} eq 'pipe') {
    Net::SSLeay::set_wfd($t{ssl}, fileno($G::link{sock}{wr})); # error check?
    Net::SSLeay::set_rfd($t{ssl}, fileno($G::link{sock}{re})); # error check?
  } else {
    Net::SSLeay::set_fd($t{ssl}, fileno($G::link{sock})); # error check?
  }
  $t{active} = Net::SSLeay::connect($t{ssl}) == 1 ? 1 : 0;
  $t{res}    = Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error())
                       if (!$t{active});
  $t{cipher} = Net::SSLeay::get_cipher($t{ssl});

  return($t{active});
}

sub ptrans {
  my $c = shift;  # transaction flag
  my $m = shift;  # message to print
  my $b = shift;  # be brief in what we print
  my $o = \*STDOUT;
  my $f;

  return if (($G::hide_send    && int($c/10) == 2) ||
             ($G::hide_receive && int($c/10) == 3));

  # global option silent controls what we echo to the terminal
  # 0 - print everything
  # 1 - don't show anything until you hit an error, then show everything
  #     received after that (done by setting option to 0 on first error)
  # 2 - don't show anything but errors
  # >=3 - don't print anything
  if ($G::silent > 0) {
    return if ($G::silent >= 3);
    return if ($G::silent == 2 && $c%2 != 0);
    if ($G::silent == 1) {
      if ($c%2 != 0) {
        return();
      } else {
        $G::silent = 0;
      }
    }
  }

  # 1x is program messages
  # 2x is smtp send
  # 3x is smtp recv
  # x = 1 is info/normal
  # x = 2 is error
  # program info
  if ($c == 11) { $f = '==='; }
  # program error
  elsif ($c == 12) { $f = '***'; $o = \*STDERR; }
  # smtp send info
  elsif ($c == 21) { $f = $G::link{tls}{active} ? ' ~>' : ' ->'; }
  # smtp send error
  elsif ($c == 22) { $f = $G::link{tls}{active} ? '*~>' : '**>'; }
  # smtp recv info
  elsif ($c == 31) { $f = $G::link{tls}{active} ? '<~ ' : '<- '; }
  # smtp recv error
  elsif ($c == 32) { $f = $G::link{tls}{active} ? '<~*' : '<**'; }
  # something went unexpectedly
  else { $c = '???'; }

  $f .= ' ';
  $f = '' if ($G::no_hints && int($c/10) != 1);

  if ($b) {
    # split to tmp list to prevent -w gripe
    my @t = split(/\n/ms, $m); $m = scalar(@t) . " lines sent";
  }
  $m =~ s/\n/\n$f/msg;
  print $o "$f$m\n";
}

sub do_smtp_quit {
  my $exit = shift;
  my $err  = shift;

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

sub do_smtp_tls {
  my $e  = shift; # ehlo config hash

  if (!$e->{STARTTLS}) {
    ptrans(12, "STARTTLS not supported");
    return $G::tls_optional ? 1 : 0;
  } elsif (!do_smtp_gen("STARTTLS", '220')) {
    return $G::tls_optional ? 1 : 0;
  } elsif (!start_tls()) {
    ptrans(12, "TLS startup failed ($G::link{tls}{res})");
    return $G::tls_optional ? 1 : 0;
  }

  ptrans(11, "TLS started w/ cipher $G::link{tls}{cipher}");
  return(1);
}

sub do_smtp_auth {
  my $e  = shift; # ehlo config hash
  my $at = shift; # auth type
  my $au = shift; # auth user
  my $ap = shift; # auth password

  # the auth_optional stuff is handled higher up, so tell the truth about
  # failing here

  # note that we don't have to check whether the modules are loaded here,
  # that's done in the option processing - trust that an auth type
  # wouldn't be in $at if we didn't have the correct tools.

  my $auth_attempted = 0; # set to true if we ever attempt auth

  foreach my $btype (@$at) {
    # if server doesn't support, skip type (may change in future)
    next if (!$e->{AUTH}{$btype});

    foreach my $type (@{$G::auth_map_t{'CRAM-MD5'}}) {
      if ($btype eq $type) {
        return(1) if (do_smtp_auth_cram($au, $ap, $type));
        $auth_attempted = 1;
      }
    }
    foreach my $type (@{$G::auth_map_t{'CRAM-SHA1'}}) {
      if ($btype eq $type) {
        return(1) if (do_smtp_auth_cram($au, $ap, $type));
        $auth_attempted = 1;
      }
    }
    foreach my $type (@{$G::auth_map_t{'DIGEST-MD5'}}) {
      if ($btype eq $type) {
        return(1) if (do_smtp_auth_digest($au, $ap, $type));
        $auth_attempted = 1;
      }
    }
    foreach my $type (@{$G::auth_map_t{'NTLM'}}) {
      if ($btype eq $type) {
        return(1) if (do_smtp_auth_ntlm($au, $ap, $type));
        $auth_attempted = 1;
      }
    }
    foreach my $type (@{$G::auth_map_t{'PLAIN'}}) {
      if ($btype eq $type) {
        return(1) if (do_smtp_auth_plain($au, $ap, $type));
        $auth_attempted = 1;
      }
    }
    foreach my $type (@{$G::auth_map_t{'LOGIN'}}) {
      if ($btype eq $type) {
        return(1) if (do_smtp_auth_login($au, $ap, $type));
        $auth_attempted = 1;
      }
    }
  }

  if ($auth_attempted) {
    ptrans(12, "No authentication type succeeded");
  } else {
    ptrans(12, "No acceptable authentication types available");
  }
  return(0);
}

sub do_smtp_auth_ntlm {
  my $u = shift; # auth user
  my $p = shift; # auth password
  my $as = shift; # auth type (since NTLM might be SPA or MSN)
  my $r = '';    # will store smtp response
  my $domain;
  ($u,$domain) = split(/%/, $u);

  my $auth_string = "AUTH $as";
  do_smtp_gen($auth_string, '334') || return(0);

  my $d = db64(Authen::NTLM::ntlm());

  $auth_string = eb64($d);
  do_smtp_gen($auth_string, '334', \$r, '', $G::auth_showpt ? "$d" : '',
              $G::auth_showpt ? \&unencode_smtp : '') || return(0);

  $r =~ s/^....//; # maybe something a little better here?
  Authen::NTLM::ntlm_domain($domain);
  Authen::NTLM::ntlm_user($u);
  Authen::NTLM::ntlm_password($p);
  $d = db64(Authen::NTLM::ntlm($r));

  $auth_string = eb64($d);
  do_smtp_gen($auth_string, '235', \$r, '',
              $G::auth_showpt ? "$d" : '') || return(0);

  return(1);
}

sub do_smtp_auth_digest {
  my $u = shift; # auth user
  my $p = shift; # auth password
  my $as = shift; # auth string
  my $r = '';    # will store smtp response

  my $auth_string = "AUTH $as";
  do_smtp_gen($auth_string, '334', \$r, '', '',
              $G::auth_showpt ? \&unencode_smtp : '')
      || return(0);

  $r =~ s/^....//; # maybe something a little better here?
  $r = db64($r);
  my $req = Authen::DigestMD5::Request->new($r);
  my $res = Authen::DigestMD5::Response->new();
  $res->got_request($req);
  # XXX using link{server} here is probably a bug, but I don;t know what else
  # XXX to use yet on a non-inet-socket connection
  $res->set('username' => $u, 'realm' => '',
            'digest-uri' => "smtp/$G::link{server}");
  $res->add_digest(password => $p);
  my $d = $res->output();
  $auth_string = eb64($d);

  do_smtp_gen($auth_string, '334', \$r, '', $G::auth_showpt ? "$d" : '',
              $G::auth_showpt ? \&unencode_smtp : '')
      || return(0);
  $r =~ s/^....//; # maybe something a little better here?
  $r = db64($r);
  $req->input($r);
  return(0) if (!$req->auth_ok);

  do_smtp_gen("", '235', undef, '',
              $G::auth_showpt ? "" : '') || return(0);
  return(1);
}

# This can handle both CRAM-MD5 and CRAM-SHA1
sub do_smtp_auth_cram {
  my $u  = shift; # auth user
  my $p  = shift; # auth password
  my $as = shift; # auth string
  my $r  = '';    # will store smtp response

  my $auth_string = "AUTH $as";
  do_smtp_gen($auth_string, '334', \$r, '', '',
              $G::auth_showpt ? \&unencode_smtp : '')
      || return(0);

  $r =~ s/^....//; # maybe something a little better here?
  # specify which type of digest we need based on $as
  my $d = get_digest($p, $r, ($as =~ /-SHA1$/ ? 'sha1' : 'md5'));
  $auth_string = eb64("$u $d");

  do_smtp_gen($auth_string, '235', undef, '',
              $G::auth_showpt ? "$u $d" : '') || return(0);
  return(1);
}

sub do_smtp_auth_login {
  my $u = shift; # auth user
  my $p = shift; # auth password
  my $as = shift; # auth string
  my $z = '';

  my $auth_string = "AUTH $as";
  do_smtp_gen($auth_string, '334', undef, '', '',
              $G::auth_showpt ? \&unencode_smtp : '') || return(0);
  $auth_string = eb64($u);
  $z = $u if ($G::auth_showpt);
  do_smtp_gen($auth_string, '334', undef, '', $z,
              $G::auth_showpt ? \&unencode_smtp : '') || return(0);
  $auth_string = eb64($p);
  $z = $p if ($G::auth_showpt);
  do_smtp_gen($auth_string, '235', undef, '', $z) || return(0);
  return(1);
}

sub do_smtp_auth_plain {
  my $u = shift; # auth user
  my $p = shift; # auth password
  my $as = shift; # auth string

  my $auth_string = "AUTH $as " . eb64("\0$u\0$p");
  my $z = '';
  if ($G::auth_showpt) {
    $z = "AUTH $as \\0$u\\0$p";
  }
  return(do_smtp_gen($auth_string, '235', undef, '', $z));
}

sub do_smtp_helo {
  my $h = shift;  # helo string to use
  my $e = shift;  # this is a hashref that will be populated w/ server options
  my $p = shift;  # protocol for the transaction
  my $r = '';     # this'll be populated by do_smtp_gen

  if ($p eq 'esmtp' || $p eq 'lmtp') {
    my $l = $p eq 'lmtp' ? "LHLO" : "EHLO";
    if (do_smtp_gen("$l $h", '250', \$r)) {
      # $ehlo is designed to hold the advertised options, but I'm not sure how
      # to store them all - for instance, SIZE is a simple key/value pair, but
      # AUTH lends itself more towards a multilevel hash.  What I'm going to do
      # is come here and add each key in the way that makes most sense in each
      # case.  I only need auth for now.
      foreach my $l (split(/\n/, $r)) {
        $l =~ s/^....//;
        if ($l =~ /^AUTH=?(.*)$/) {
          map { $e->{AUTH}{uc($_)} = 1 } (split(' ', $1));
        } elsif ($l =~ /^STARTTLS$/) {
          $e->{STARTTLS} = 1;
        } elsif ($l =~ /^PIPELINING$/) {
          $e->{PIPELINING} = 1;
          $G::pipeline_adv = 1;
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
  my $m = shift;  # from address

  transact(cxn_string => "MAIL FROM:<$m>", expect => '250', defer => 1,
           fail_callback => \&smtp_mail_callback);

  return(1); # the callback handles failures, so just return here
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
    #$f++ if (!do_smtp_gen("RCPT TO:<$addr>", '250'));
    transact(cxn_string => "RCPT TO:<$addr>", expect => '250', defer => 1,
             fail_callback => \&smtp_rcpt_callback);
  }

  return(1); # the callback handles failures, so just return here

#  # if at least one addr succeeded, we can proceed, else we stop here
#  return $f == scalar(@a) ? 0 : 1;
}

sub smtp_rcpt_callback {
  # record that a failure occurred
  $G::smtp_rcpt_failures++;

  # if the number of failures is the same as the total rcpts (if every rcpt
  # rejected), quit.
  if ($G::smtp_rcpt_failures == $G::smtp_rcpt_total) {
    do_smtp_quit(1, 24);
  }
}

sub do_smtp_data {
  my $m = shift; # string to send
  my $b = shift; # be brief in the data we send
  my $calls = $G::smtp_rcpt_total - $G::smtp_rcpt_failures;

  my $ok = transact(cxn_string => $m, expect => '250', summarize_output => $b);

  # now be a little messy - lmtp is not a lockstep after data - we need to
  # listen for as many calls as we had accepted recipients
  if ($G::protocol eq 'lmtp') {
    foreach my $c (1..($calls-1)) { # -1 because we already got 1 above
      $ok += transact(cxn_string => undef, expect => '250');
    }
  }
  return($ok)
}

sub do_smtp_gen {
  my $m = shift; # string to send
  my $e = shift; # String we're expecting to get back
  my $p = shift; # this is a scalar ref, assign the server return string to it
  my $b = shift; # be brief in the data we send
  my $x = shift; # if this is populated, print this instead of $m
  my $c = shift; # if this is a code ref, call it on the return value b4 print
  my $r = '';    # This'll be the return value from transact()
  my $time;

  return transact(cxn_string => $m, expect => $e, return_text => $p,
                  summarize_output => $b, show_string => $x,
                  print_callback => $c);
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
  $G::send_buffer = '';
}

sub send_data {
  my $d = shift; # data to write
  $G::send_buffer .= "$d\r\n";
}

sub recv_line {
  # Either an IO::Socket obj or a FH to my child - the thing to read from
  my $s = $G::link{type} eq 'pipe' ? $G::link{sock}->{re} : $G::link{sock};
  my $r = undef;

  if ($G::link{tls}{active}) {
    $r = Net::SSLeay::read($G::link{tls}{ssl});
  } else {
    $r = <$s>;
  }
  $r =~ s|\r||msg;
#print "in recv_line, returning \$r = $r\n";
  return($r);
}

# any request which has immediate set will be checking the return code.
# any non-immediate request will handle results through fail_callback().
# therefore, only return the state of the last transaction attempted,
# which will always be immediate
# We still need to reimplement timing
sub transact {
  my %h        = @_; # this is an smtp transaction element
  my $ret      = 1;  # this is our return value
  my @handlers = (); # will hold and fail_handlers we need to run
  my $time     = ''; # used in time lapse calculations

  push(@G::pending_send, \%h); # push onto send queue
  if (!($G::pipeline && $G::pipeline_adv) || !$h{defer}) {

    if ($G::show_time_lapse) {
      if ($G::show_time_hires) { $time = [Time::HiRes::gettimeofday()];   }
      else                     { $time = time(); }
    }

    while (my $i = shift(@G::pending_send)) {
      if ($i->{cxn_string}) {
        ptrans(21,$i->{show_string}||$i->{cxn_string},$i->{summarize_output});
        send_data($i->{cxn_string});
      }
      push(@G::pending_recv, $i);
    }
    flush_send_buffer();
    while (my $i = shift(@G::pending_recv)) {
      my $buff = '';
      eval {
        local $SIG{'ALRM'} = sub {
          $buff ="Timeout ($G::link{timeout} secs) waiting for server response";
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

      if ($G::show_time_lapse) {
        if ($G::show_time_hires) {
          $time = sprintf("%0.03f", Time::HiRes::tv_interval($time,
                                   [Time::HiRes::gettimeofday()]));
          ptrans(11, "response in ${time}s");
          $time = [Time::HiRes::gettimeofday()];
        } else {
          $time = time() - $time;
          ptrans(11, "response in ${time}s");
          $time = time();
        }
      }

      ${$i->{return_text}} = $buff;
      $buff = &{$i->{print_callback}}($buff)
          if (ref($i->{print_callback}) eq 'CODE');
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

sub unencode_smtp {
  my $t = shift;

  my @t = split(' ', $t);
  return("$t[0] " . db64($t[1]));
}

sub process_file {
  my $f = shift;
  my $h = shift;

  if (! -e "$f") {
    ptrans(12, "File $f does not exist, skipping");
    return;
  } elsif (! -f "$f") {
    ptrans(12, "File $f is not a file, skipping");
    return;
  } elsif (!open(I, "<$f")) {
    ptrans(12, "Couldn't open $f, skipping... ($!)");
    return;
  }

  while (<I>) {
    chomp;
    next if (/^#?\s*$/); # skip blank lines and those that start w/ '#'
    my($key,$value) = split(' ', $_, 2);
    $h->{uc($key)} = $value;
  }
  return;
}

sub interact {
  my($prompt) = shift;
  my($regexp) = shift;
  my($continue) = shift;
  my($response) = '';

  do {
    print "$prompt";
    chomp($response = <STDIN>);
  } while ($regexp ne 'SKIP' && $response !~ /$regexp/);

  return($response);
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

  if ($addr =~ /\@\[(\d+\.\d+\.\d+\.\d+)\]$/) {
    # handle automatic routing of domain literals (user@[1.2.3.4])
    return($1);
  } elsif ($addr =~ /\@\#(\d+)$/) {
    # handle automatic routing of decimal domain literals (user@#16909060)
    $addr = $1;
    return(($addr/(2**24))%(2**8) . '.' . ($addr/(2**16))%(2**8) . '.'
          .($addr/(2**8))%(2**8)  . '.' . ($addr/(2**0))%(2**8));
  }



  if (!avail("dns")) {
    ptrans(12, avail_str("dns").".  Using $server as mail server");
    return($server);
  }
  my $res = new Net::DNS::Resolver;

  return($server) if ($addr !~ /\@/);

  $addr =~ s/^.*\@([^\@]*)$/$1/;
  return($server) if (!$addr);
  $server = $addr;

  my @mx = mx($res, $addr);
  foreach my $rr (@mx) {
    if ($rr->preference < $pref || $pref == -1) {
      $pref   = $rr->preference;
      $server = $rr->exchange;
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
    $s->{$f}{errstr} = "$s->{$f}{name} not available: requires "
                     . join(', ', @{$s->{$f}{req_failed}});
    if (scalar(@{$s->{$f}{opt_failed}})) {
      $s->{$f}{errstr} .= ".  Also missing optimizing "
                        . join(', ', @{$s->{$f}{opt_failed}});
    }
    return $s->{$f}{avail} = 0;
  } else {
    if (scalar(@{$s->{$f}{opt_failed}})) {
      $s->{$f}{errstr} = "$s->{$f}{name} supported, but missing optimizing "
                       . join(', ', @{$s->{$f}{opt_failed}});
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
      $secr = Digest::SHA1::sha1($secr);
    }
  } else {
    $secr .= chr(0) x (64 - length($secr));
  }

  my $digest = $type eq 'md5'
               ? Digest::MD5::md5_hex(($secr ^ $opad),
                 Digest::MD5::md5(($secr ^ $ipad), $chal))
               : Digest::SHA1::sha1_hex(($secr ^ $opad),
                 Digest::SHA1::sha1(($secr ^ $ipad), $chal));
  return($digest);
}

sub test_support {
  my $s = \%G::dependencies;

  foreach my $act (sort { $s->{$a}{name} cmp $s->{$b}{name} } keys %$s) {
    ptrans(avail($act) ? 11 : 12, avail_str($act));
    #if (avail($act)) {
    #  #ptrans(11, "$s->{$act}{name} supported");
    #  ptrans(11, avail_err($act));
    #} else {
    #  ptrans(12, avail_err($act));
    #}
  }
}

sub time_to_seconds {
  my $t = shift || 30;

  if ($t !~ /^(\d+)([hms])?/i) {
    return(30); # error condition - just use default value
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

# A couple of global options are set in here, they will be in the G:: namespace
sub process_args {
  my $o     = shift; # This is the args we got from command line
  my %n     = ();    # This is the hash we will return w/ the fixed-up args
  my $fconf = {};    # Hold config info from -l file if specified

  # load the $fconf hash if user has specified a -l file
  process_file($o->{option_file}, $fconf) if ($o->{option_file});

  $G::dump_args     = 1 if ($o->{dump_args});
  $G::suppress_data = 1 if ($o->{suppress_data});
  $G::no_hints      = 1 if ($o->{no_hints});
  $G::hide_send     = 1 if ($o->{hide_send});
  $G::hide_receive  = 1 if ($o->{hide_receive});
  $G::pipeline      = 1 if ($o->{pipeline});
  $G::silent        = $o->{silent} ? $o->{silent} : 0;

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
  $G::protocol = lc($o->{mail_protocol}) || 'esmtp';
  if (!$protos{$G::protocol}) {
    ptrans(12, "Unknown protocol $G::protocol specified, exiting");
    exit(1);
  }
  if ($protos{$G::protocol}{auth} && !$o->{auth_user} && !$o->{auth_pass} &&
      !$o->{auth_optional} && !$o->{auth})
  {
    $o->{auth} = ''; # cause auth to be processed below
  }
  if ($protos{$G::protocol}{tls} && !$o->{tls} && !$o->{tls_optional} &&
      !$o->{tls_on_connect})
  {
    if ($protos{$G::protocol}{tls} eq 's') {
      $o->{tls} = '';
    } elsif ($protos{$G::protocol}{tls} eq 'c') {
      $o->{tls_on_connect} = '';
    }
  }
  $G::protocol = $protos{$G::protocol}{proto};

  # set global option of -q option
  if ($o->{quit_after}) {
    $G::quit_after = lc($o->{quit_after});
    if ($G::quit_after =~ /^[el]hlo$/)     { $G::quit_after = 'helo';       }
    elsif ($G::quit_after =~ /first-[el]hlo/) { $G::quit_after = 'first-helo'; }
    elsif ($G::quit_after eq 'starttls')   { $G::quit_after = 'tls';        }
    elsif ($G::quit_after eq 'from')       { $G::quit_after = 'mail';       }
    elsif ($G::quit_after eq 'to')         { $G::quit_after = 'rcpt';       }
    elsif ($G::quit_after ne 'connect' && $G::quit_after ne 'first-helo' &&
           $G::quit_after ne 'tls'     && $G::quit_after ne 'helo'       &&
           $G::quit_after ne 'auth'    && $G::quit_after ne 'mail'       &&
           $G::quit_after ne 'rcpt')
    {
      ptrans(12, "Unknown quit value $G::quit_after, exiting");
      exit(1);
    }
    # only rcpt _requires_ a to address
    $G::server_only = 1 if ($G::quit_after ne 'rcpt');
  } else {
    $G::quit_after = '';
  }

  # set global flag for -stl flag
  $G::show_time_lapse = time() if (defined($o->{show_time_lapse}));
  $G::show_time_hires = 1 if ($G::show_time_lapse &&
                              avail("hires_timing") &&
                              $o->{show_time_lapse} !~ /^i/i);

  if ($o->{emulate_mail}) { # set up for -m option
    $n{to} = shift if (!defined($o->{mail_to}));
    $o->{mail_data} = ''; # define it here so we get it on stdin later
  }

  # pipe command, if one is specified
  $G::link{process}   = $o->{pipe_cmd} || interact("Pipe: ", '^.+$')
      if (defined($o->{pipe_cmd}));
  $G::link{process} ||= $fconf->{PIPE} || "";
  if ($G::link{process}) { $G::link{type} = 'pipe';   }
  else                   { delete($G::link{process}); }

  # socket file, if one is specified
  $G::link{sockfile}   = $o->{socket} || interact("Socket File: ", '^.+$')
      if (defined($o->{socket}));
  $G::link{sockfile} ||= $fconf->{SOCKET} || "";
  if ($G::link{sockfile}) { $G::link{type} = 'socket-unix'; }
  else                    { delete($G::link{sockfile});     }

  my $user     = get_username($o->{force_getpwuid});
  my $hostname = get_hostname();

  # SMTP mail from
  $n{from} = $o->{mail_from} || interact("From: ", '^.*$')
      if (defined($o->{mail_from}));
  $n{from} ||= $fconf->{FROM} || ($hostname || ($G::server_only &&
                                                $G::quit_after ne 'mail')
                                    ? "$user\@$hostname"
                                    : interact("From: ", '^.*$'));
  $n{from} = '' if ($n{from} eq '<>');

  # SMTP helo/ehlo
  $n{helo}   = $o->{mail_helo} || interact("Helo: ", '^.*$')
      if (defined($o->{mail_helo}));
  $n{helo} ||= $fconf->{HELO} || ($hostname || ($G::quit_after eq 'connect')
                                    ? $hostname
                                    : interact("Helo: ", '^.*$'));

  # SMTP server and rcpt to are interdependant, so they are handled together
  $G::link{server}   = $o->{mail_server} || interact("Server: ", '^.*$')
      if (defined($o->{mail_server}));
  $G::link{server} ||= $fconf->{SERVER};
  $n{to}             = $o->{mail_to} || interact("To: ", '^.*$')
      if (defined($o->{mail_to}));
  $n{to}           ||= $fconf->{TO};
  $n{to}             = interact("To: ", '^.*$')
      if (!$n{to} && !($G::server_only && ($G::link{server} ||
                                           $G::link{type} eq 'socket-unix' ||
                                           $G::link{type} eq 'pipe')));
  if (!$G::link{type}) {
    $G::link{server} = get_server($n{to}) if (!$G::link{server});
    $G::link{type}   = "socket-inet";
  }

  # Verify we are able to handle the requested transport
  if ($G::link{type} eq 'pipe') {
    if (!avail("pipe")) {
      ptrans(12, avail_str("pipe").".  Exiting");
      exit(2);
    }
  } else {
    if (!avail("socket")) {
      ptrans(12, avail_str("socket").".  Exiting");
      exit(2);
    }
  }

  # local interface to connect from
  $G::link{lint}   = $o->{lint} || interact("Interface: ", '^.*$')
      if (defined($o->{lint}));
  $G::link{lint} ||= $fconf->{INTERFACE} || '0.0.0.0';

  # SMTP timeout
  $o->{timeout}       = '0s' if ($o->{timeout} eq '0'); # used 'eq' on purpose
  $G::link{timeout}   = $o->{timeout} || interact("Timeout: ", '^\d+[hHmMsS]?$')
      if (defined($o->{timeout}));
  $G::link{timeout} ||= $fconf->{TIMEOUT} || '30s';
  $G::link{timeout}   = time_to_seconds($G::link{timeout});

  my $body  = 'This is a test mailing'; # default message body
  my $bound = "";
  my $stdin = undef;
  if (defined($o->{body_822})) {
    # the --body option is the entire 822 body and trumps and other options
    # that mess with the body
    if (!$o->{body_822}) {
      $body = interact("Body: ", '.+');
    } elsif ($o->{body_822} eq '-') {
      $stdin = join('', <STDIN>);
      $body  = $stdin;
    } else {
      $body = $o->{body_822};
    }
    if (open(I, "<$body")) {
      $body = join('', <I>);
      close(I);
    }
  }
  if (scalar(@{$o->{attach_822}})) {
    # this option is a list of files (or STDIN) to attach.  In this case,
    # the message become a mime message and the "body" goes in the
    # first text/plain part
    my $mime_type = 'application/octet-stream';
    my @parts = ( { body => $body, type => 'text/plain' } );
    $bound = "----=_MIME_BOUNDARY_000_$$";
    while (defined(my $t = shift(@{$o->{attach_822}}))) {
      if ($t =~ m|^[^/]+/[^/]+$| && !stat($t)) {
        $mime_type = $t;
      } else {
        push(@parts, { body => "$t", type => $mime_type });
      }
    }
    $body = '';
    foreach my $p (@parts) {
      if ($p->{body} eq '-') {
        if ($stdin) {
          $p->{body} = $stdin;
        } else {
          $p->{body} = join('', <STDIN>);
          $stdin     = $p->{body};
        }
      } elsif (open(I, "<$p->{body}")) {
        $p->{body} = join('', <I>);
        close(I);
      }
      $body .= "--$bound\n"
            .  "Content-Type: $p->{type}\n";
      if ($p->{type} =~ m|^text/plain$|i) {
        $body .= "\n" . $p->{body} . "\n";
      } else {
        $body .= "Content-Transfer-Encoding: BASE64\n"
              .  "Content-Disposition: attachment\n"
              .  "\n"
              .  eb64($p->{body}, "\n") . "\n";
      }
    }
    $body .= "--$bound--\n";
  }

  # add-header option.  In a strict technical sense all this is is a text
  # string that will replace %H in the DATA.  Because of where %H is placed
  # in the default DATA, in practice this is used to add headers to the stock
  # DATA w/o having to craft a custom DATA portion
  #if (scalar(@{$o->{add_header}})) {
  #  $n{add_header} = join("\n", @{$o->{add_header}}) . "\n";
  #}
  @{$o->{add_header}} = map { split(/\\n/) } @{$o->{add_header}};

  # SMTP DATA
  # a '-' arg to -d is the same as setting -g
  if ($o->{mail_data} eq '-') {
    undef($o->{mail_data});
    $o->{data_on_stdin} = 1;
  }
  if (defined($o->{mail_data}) && !defined($o->{data_on_stdin})) {
    if (defined($o->{emulate_mail})) {
      $n{data} = "Subject: " . interact("Subject: ", 'SKIP') . "\n\n";
      do {
        $n{data} .= interact('', 'SKIP') . "\n";
      } while ($n{data} !~ /\n\.\n$/ms);
      $n{data} =~ s/\n\.\n$//ms;
    } else {
      $n{data} = $o->{mail_data} || interact("Data: ", '^.*$');
    }
  }
  $n{data} ||= $fconf->{DATA}
           || 'Date: %D\nTo: %T\nFrom: %F\nSubject: test %D\n'
             ."X-Mailer: swaks v$p_version jetmore.org/john/code/#swaks".'\n'
             . ($bound ?  'MIME-Version: 1.0\n'
                         .'Content-Type: multipart/mixed; '
                         .'boundary="'.$bound.'"\n'
                       : '')
             .'%H' # newline will be added in replacement if it exists
             .'\n'
             .'%B\n';
  # The -g option trumps all other methods of getting the data
  $n{data}   = join('', <STDIN>) if ($o->{data_on_stdin});
  if (!$o->{no_data_fixup}) {
    $n{data} =~ s/%B/$body/g;
    if (scalar(@{$o->{header}})) {
      my %matched = ();
      foreach my $l (map { split(/\\n/) } @{$o->{header}}) {
        if (my($h) = $l =~ /^([^:]+):/) {
          if (!$matched{$h} && $n{data} =~ s/(^|\\n)$h:.*?($|\\n)/$1$l$2/) {
            $matched{$h} = 1;
          } else { push(@{$o->{add_header}}, $l); }
        } else { push(@{$o->{add_header}}, $l); }
      }
    }
    $n{add_header} = join('\n', @{$o->{add_header}}) . "\n"
        if (@{$o->{add_header}});
    $n{data} =~ s/%H/$n{add_header}/g;
    $n{data} =~ s/\\n/\r\n/g;
    $n{data} =~ s/%F/$n{from}/g;
    $n{data} =~ s/%T/$n{to}/g;
    $n{data} =~ s/%D/get_date_string()/eg;
    $n{data} =~ s/^From [^\n]*\n// if (!$O{no_strip_from});
    $n{data} =~ s/\r?\n\.\r?\n?$//s;   # If there was a trailing dot, remove it
    $n{data} =~ s/\n\./\n../g;         # quote any other leading dots
    # translate line endings - run twice to get consecutive \n correctly
    $n{data} =~ s/([^\r])\n/$1\r\n/gs;
    $n{data} =~ s/([^\r])\n/$1\r\n/gs; # this identical call not a bug
    $n{data} .= "\r\n.";               # add a trailing dot
  }

  # Handle TLS options
  $G::tls_optional      = 1 if (defined($o->{tls_optional}));
  $G::tls               = 1 if (defined($o->{tls}) || $G::tls_optional);
  $G::tls_on_connect    = 1 if (defined($o->{tls_on_connect}));
  $G::link{tls}{active} = 0;
  if ($G::tls || $G::tls_on_connect) {
    if (!avail("tls")) {
      if ($G::tls_optional) {
        $G::tls = undef; # so we won't try it later
        ptrans(12,avail_str("tls").".  Skipping optional TLS");
      } else {
        ptrans(12,avail_str("tls").".  Exiting");
        exit(10);
      }
    }
  }

  # SMTP port
  $G::link{port}   = $o->{mail_port} || interact("Port: ", '^\w+$')
      if (defined($o->{mail_port}));
  $G::link{port} ||= $fconf->{PORT};
  if ($G::link{port}) {
    # in here, the user has either specified a port, or that they _want_
    # to, so if it isn't a resolvable port, ,keep prompting for another one
    my $o_port = $G::link{port};
    if ($G::link{port} !~ /^\d+$/) {
      $G::link{port} = getservbyname($G::link{port}, 'tcp');
      while (!$G::link{port}) {
        $G::link{port} = $o_port =
            interact("Unable to resolve port $o_port\nPort: ", '^\w+$');
        $G::link{port} = getservbyname($G::link{port}, 'tcp')
            if ($G::link{port} !~ /^\d+$/);
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
  

  # Handle AUTH options
  $G::auth_optional = 1 if (defined($o->{auth_optional}));
  $o->{auth_types} = [];
  if ($o->{auth}) {
    @{$o->{auth_types}} = map { uc($_) } (split(/,/, $o->{auth}));
  } elsif ($o->{auth_optional}) {
    @{$o->{auth_types}} = map { uc($_) } (split(/,/, $o->{auth_optional}));
  } elsif (defined($o->{auth_user}) || defined($o->{auth_pass}) ||
           $G::auth_optional || (defined($o->{auth}) && !$o->{auth}))
  {
    $o->{auth_types}[0] = 'ANY';
    $o->{auth} = 'ANY'; # this is checked below
  }
  # if after that processing we've defined some auth type, do some more
  # specific processing
  if (scalar(@{$o->{auth_types}})) {
    # there's a lot of option processing below.  If any type looks like it
    # will succeed later, set this to true
    my $valid_auth_found = 0;

    # handle the --auth-map options plus our default mappings
    foreach (split(/\s+,\s+/, $o->{auth_map}),"PLAIN=PLAIN","LOGIN=LOGIN",
             "CRAM-MD5=CRAM-MD5","DIGEST-MD5=DIGEST-MD5","CRAM-SHA1=CRAM-SHA1",
             "NTLM=NTLM","SPA=NTLM","MSN=NTLM")
    {
      my($alias,$type) = split(/=/, uc($_), 2);
      # this gives us a list of all aliases and what the alias
      $G::auth_map_f{$alias} = $type;
      # this gives a list of all base types and any aliases for it.
      $G::auth_map_t{$type} ||= [];
      push(@{$G::auth_map_t{$type}}, $alias);
    }
    if (!avail("auth")) { # check for general auth requirements
      if ($G::auth_optional) {
        ptrans(12, avail_str("auth"). ".  Skipping optional AUTH");
      } else {
        ptrans(12, avail_str("auth"). ".  Exiting");
        exit(10);
      }
    } else {
      # if the user doesn't specify an auth type, create a list from our
      # auth-map data.  Simplifies processing later
      if ($o->{auth_types}[0] eq 'ANY') {
        $o->{auth_types} = [sort keys %G::auth_map_f];
      }

      foreach my $type (@{$o->{auth_types}}) {
        # we need to evaluate whether we will be able to run the auth types
        # specified by the user

        if (!$G::auth_map_f{$type}) {
          ptrans(12, "$type is not a recognized auth type, skipping");
        }

        elsif ($G::auth_map_f{$type} eq 'CRAM-MD5' && !avail("auth_cram_md5"))
        {
          ptrans(12, avail_str("auth_cram_md5")) if ($o->{auth} ne 'ANY');
        }

        elsif ($G::auth_map_f{$type} eq 'CRAM-SHA1' && !avail("auth_cram_sha1"))
        {
          ptrans(12, avail_str("auth_cram_sha1")) if ($o->{auth} ne 'ANY');
        }

        elsif ($G::auth_map_f{$type} eq 'NTLM' && !avail("auth_ntlm"))
        {
          ptrans(12, avail_str("auth_ntlm")) if ($o->{auth} ne 'ANY');
        }

        elsif ($G::auth_map_f{$type} eq 'DIGEST-MD5' &&
               !avail("auth_digest_md5"))
        {
          ptrans(12, avail_str("auth_digest_md5")) if ($o->{auth} ne 'ANY');
        }

        else {
          $valid_auth_found = 1;
          push(@{$n{a_type}}, $type);
        }

      } # foreach

      if (!$valid_auth_found) {
        ptrans(12, "No auth types supported");
        if (!$G::auth_optional) {
          exit(10);
        }
        $n{a_user} = $n{a_pass} = $n{a_type} = undef;
      } else {
        $n{a_user}   = $o->{auth_user} if (defined($o->{auth_user}));
        $n{a_user} ||= $fconf->{USER};
        $n{a_user} ||= interact("Username: ", 'SKIP');
        $n{a_user}   = '' if ($n{a_user} eq '<>');

        $n{a_pass}   = $o->{auth_pass} if (defined($o->{auth_pass}));
        $n{a_pass} ||= $fconf->{PASS};
        $n{a_pass} ||= interact("Password: ", 'SKIP');
        $n{a_pass}   = '' if ($n{a_pass} eq '<>');

        $G::auth_showpt = 1 if (defined($o->{auth_showpt}));
        # This option is designed to hide passwords - turn echo off when
        # supplying at PW prompt, star out the PW strings in AUTH transactions.
        # Not implementing right now - the echo might be a portability issue,
        # and starring out is hard because the smtp transaction is abstracted
        # beyond where this is easy to do.  Maybe sometime in the future
        #$G::auth_hidepw = 1 if (defined($o->{auth_hidepw}));
      }
    } # end avail("auth")
  } # end auth parsing

  return(\%n);
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
  return getlogin() || (getpwuid($<))[0];
}

sub get_date_string {
  return($G::date_string) if (length($G::date_string) > 0);

  my @l = localtime();
  my $o = 0;

  if (!avail("date_manip")) {
    ptrans(12, avail_str("date_manip").".  Date strings will be in GMT");
    @l = gmtime();
  } else {
    my @g = gmtime();
    $o = (timelocal(@l) - timelocal(@g))/36;
  }
  $G::date_string = sprintf("%s, %02d %s %d %02d:%02d:%02d %+05d",
                 (qw(Sun Mon Tue Wed Thu Fri Sat))[$l[6]],
                 $l[3],
                 (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$l[4]],
                 $l[5]+1900, $l[2], $l[1], $l[0],
                 $o
  );
}

# partially Cribbed from "Programming Perl" and MIME::Base64 v2.12
sub db64 {
  my $s =  shift;
  if (load("MIME::Base64")) {
    return(decode_base64($s));
  } else {
    $s    =~ tr#A-Za-z0-9+/##cd;
    $s    =~ s|=+$||;
    $s    =~ tr#A-Za-z0-9+/# -_#;
    my $r = '';
    while ($s =~ s/(.{1,60})//s) {
      $r .= unpack("u", chr(32 + int(length($1)*3/4)) . $1);
    }
    return($r);
  }
}

# partially Cribbed from MIME::Base64 v2.12
sub eb64 {
  my $s    =  shift;
  my $e    =  shift || ''; # line ending to use "empty by default"
  if (load("MIME::Base64")) {
    return(encode_base64($s, $e));
  } else {
    my $l    =  length($s);
    chomp($s =  pack("u", $s));
    $s       =~ s|\n.||gms;
    $s       =~ s|\A.||gms;
    $s       =~ tr#` -_#AA-Za-z0-9+/#;
    my $p    =  (3 - $l%3) % 3;
    $s       =~ s/.{$p}$/'=' x $p/e if ($p);
    $s       =~ s/(.{1,76})/$1$e/g if (length($e));
    return($s);
  }
}

sub ext_usage {
  if ($ARGV[0] =~ /^--help$/i) {
    require Config;
    $ENV{PATH} .= ":" unless $ENV{PATH} eq "";
    $ENV{PATH} = "$ENV{PATH}$Config::Config{'installscript'}";
    $< = $> = 1 if ($> == 0 || $< == 0);
    exec("perldoc", $0) || exit(1);
    # make parser happy
    %Config::Config = ();
  } elsif ($ARGV[0] =~ /^--version$/i) {
    print "$p_name version $p_version\n\n$p_cp\n";
  } else {
    return;
  }

  exit(0);
}

__END__

=head1 NAME

swaks - SMTP transaction tester

=head1 USAGE

swaks [--help|--version] | (see description of options below)

=head1 OPTIONS

=over 4

=item --pipe

This option takes as its argument a program and the program's arguments.  If this option is present, swaks opens a pipe to the program and enters an SMTP transaction over that pipe rather than connecting to a remote server.  Some MTAs have testing modes using stdin/stdout.  This option allows you to tie into those options.  For example, if you implemented DNSBL checking with exim and you wanted to make sure it was working, you could run 'swaks --pipe "exim -bh 127.0.0.2"'.

In an ideal world the process you are talking to should behave exactly like an SMTP server on stdin and stdout.  Any debugging should be sent to stderr, which will be directed to your terminal.  In the real world swaks can generally handle some debug on the child's stdout, but there are no guarantees on how much it can handle.

=item --socket

This option takes as its argument a unix domain socket file.  If this option is present, swaks enters an SMTP transaction over over the unix domains socket rather than over an internet domain socket.  I think this option has uses when combined with a (yet unwritten) LMTP mode, but to be honest at this point I just implemented it because I could.

=item -l, --input-file

Argument to -l must be a path to a file containing TOKEN->VALUE pairs.  The TOKEN and VALUE must be separated by whitespace.  These tokens set values which would otherwise be set by command line arguments.  See the description of the corresponding command line argument for details of each token.  Valid tokens are FROM (-f), TO (-t), SERVER (-s), DATA (-d), HELO (-h), PORT (-p), INTERFACE (-li), and TIMEOUT (-to).

=item -t, --to

Use argument as "RCPT TO" address, or prompt user if no argument specified.  Overridden by -l token TO.  Multiple recipients can be specified by supplying as one comma-delimited argument.

There is no default for this option.  If no to addess is specified with -t or TO token, user will be prompted for To: address on STDIN.

=item -f, --from

Use argument as "MAIL FROM" address, or prompt user if no argument specified.  Overridden by -l token FROM.  If no from address is specified, default is user@host, where user is the best guess at user currently running program, and host is best guess at DNS hostname of local host.  The string <> can be supplied to mean the null sender.

=item -s, --server

Use argument as mail server to which to connect, or prompt user if no argument specified.  Overridden by -l token SERVER.  If unspecified, swaks tries to determine primary MX of destination address.  If Net::DNS module is not available, tries to connect to A record for recipient's domain.

=item -p, --port

Use argument as port to connect to on server, or prompt user if no argument is specified.  This can be either a port number or a service name.  Overridden by -l token PORT.  If unspecified, swaks will use service lmtp if --protocol is LMTP, service smtps if --tls-on-connect is used, and smtp otherwise.

=item -h, --helo, --ehlo

Use argument as argument to SMTP EHLO/HELO command, or prompt use if no argument is specified.  Overridden by -l token HELO.  If unspecified, swaks uses best guess at DNS hostname of local host.

=item -d, --data

Use argument as DATA portion of SMTP transaction, or prompt user if no argument specified.  Overridden by -l token DATA.

This string should be on one single line, with a literal \n representing where line breaks should be placed.  Leading dots will be quoted.  Closing dot is not required but is allowed.  Very basic token parsing is done.  %F is replaced with the value that will be used for "MAIL FROM", %T is replaced with "RCPT TO" values, %D is replaced with a timestamp, %H is replaced with the contents of --add-header, and %B is replaced with the message body.  See the --body option for the default body text.

Default value for this option is "Date: %D\nTo: %T\nFrom: %F\nSubject: test %D\nX-Mailer: swaks v$p_version jetmore.org/john/code/#swaks\n%H\n\n%B\n".

=item --body

Specify the body of the email.  The default is "This is a test mailing".  If no argument to --body, you will be prompted to supply one.  If '-' is supplied, body will be read from standard input.  If any other text is provided and the text represents an openable file, the content of that file is used as the body.  If it does not respresent an openable file, the text itself is used as the body.

=item --attach

When one or more --attach option is supplied, the message is changed into a multipart/mixed MIME message.  The arguments to --attach are processed the same as --body with regard to stdin, file contents, etc.  --attach can be supplie multiple times to create multiple attachments.  By default each attachment is attached as a application/octet-stream file.  See --attach-type for changing this behaviour.

When the message changes to MIME format, the previous body (%B) is attached as a text/plain type as the first attachment.  --body can still be used to specify the contents of this body attachment.

It is legal for '-' (STDIN) to be specified as an argument multiple times (once for --body and multiple times for --attach).  In this case, the same content will be attached each time it is specified.  This is useful for attaching the same content with multiple MIME types.

=item --attach-type

By default, content that gets MIME attached to a message with the --attach option is encoded as application/octet-stream.  --attach-type changes the mime type for every --attach option which follows it.  It can be specified multiple times.

=item -ah, --add-header

In the strictest sense, all this does is provide a value that replaces the %H token in the data.  Because of where %H is located in the default DATA, practically it is used to add custom headers without having to recraft the entire body.

The option can either be specified multiple times or a single time with multiple headers seperated by a literal '\n' string.  So, "--add-header 'Foo: bar' --add-header 'Baz: foo'" and "--add-header 'Foo: bar\nBaz: foo'" end up adding the same two headers.

=item --header, --h-Header

These options allow a way to change headers that already exist in the DATA.  These two calls do the same thing:

--header "Subject: foo"
--h-Subject foo

Subject is the example used.  If the header does not exist in the body already, these calls behave identically to --add-header.  The purpose of this option it to provide a fast way to change the nature of the default DATA for specific tests.  For instance if you wanted to test a subject filer in a mail system, you could use --h-Subject "SPAM STRING" to test rather than having to craft and entire new DATA string to pass to --data.

=item --timeout

Use argument as the SMTP transaction timeout, or prompt user if no argument given.  Overridden by the -l token TIMEOUT.  Argument can either be a pure digit, which will be interpretted as seconds, or can have a specifier s or m (5s = 5 seconds, 3m = 180 seconds).  As a special case, 0 means don't timeout the transactions.  Default value is 30s.

=item --protocol

Specify which protocol to use in the transaction.  Valid options are shown in the table below.  Currently the 'core' protocols are SMTP, ESMTP, and LMTP.  By using variations of these protocol types one can specify default ports, whether authentication should be attempted, and the type of TLS connection that should be attempted.  The default protocol is ESMTP.  This table demonstrates the available arguments to --protocol and the options each sets as a side effect:

           HELO            AUTH    TLS     PORT
   --------------------------------------------------
   SMTP    HELO                            smtp  / 25
   SSMTP   EHLO->HELO              -tlsc   smtps / 465
   SSMTPA  EHLO->HELO      -a      -tlsc   smtps / 465
   SMTPS   HELO                    -tlsc   smtps / 465
   ESMTP   EHLO->HELO                      smtp  / 25
   ESMTPA  EHLO->HELO      -a              smtp  / 25
   ESMTPS  EHLO->HELO              -tls    smtp  / 25
   ESMTPSA EHLO->HELO      -a      -tls    smtp  / 25
   LMTP    LHLO                            lmtp  / 24
   LMTPA   LHLO            -a              lmtp  / 24
   LMTPS   LHLO                    -tls    lmtp  / 24
   LMTPSA  LHLO            -a      -tls    lmtp  / 24

=item -li, --local-interface

Use argument as the local interface for the SMTP connection, or prompt user if no argument given.  Overridden by the -l token INTERFACE.  Argument can be an IP or a hostname.  Default action is to let OS choose local interface.

=item -g

If specified, swaks will read the DATA value for the mail from STDIN.  If there is a From_ line in the email, it will be removed (but see -nsf option).  Useful for delivering real message (stored in files) instead of using example messages.

=item -nsf, --no-strip-from

Don't strip the From_ line from the DATA portion, if present.

=item -n, --suppress-data

If this option is specified, swaks summarizes the DATA portion of the SMTP transaction instead of printing every line.

=item -q, --quit-after

The argument to this option is used as an indicator of where to quit the SMTP transaction.  It can be thought of as "quit after", with valid arguments CONNECT, FISRT-HELO, TLS, HELO, AUTH, MAIL, and RCPT.  In a non-STARTTLS session, FIRST-HELO and HELO behave the same way.  In a STARTTLS session, FIRST-HELO quits after the first HELO sent, while HELO quits after the second HELO is sent.

For convenience, LHLO and EHLO are synonyms for HELO, FIRST-EHLO and FIRST-LHLO for FIRST-HELO, FROM for MAIL, and TO for RCPT.

=item -m

Emulate Mail command.  Least used option in swaks.

=item --support

Cause swaks to print its capabilities and exit.  Certain features require non-standard perl modules.  This options evaluates whether these modules are present and lets you know which functionality is present.

=item -S, --silent

Cause swaks to be silent.  "-S" causes swaks to print no output until an error occurs, after which all output is shown.  "-S -S" causes swaks to only show error conditions.  "-S -S -S" shows no output.

=item --pipeline

If the remote server supports it, attempt SMTP PIPELINING (RFC 2920).  This is a younger option, if you experience problems with it please notify the author.  Potential problem areas include servers accepting DATA even though there were no valid recipients (swaks should send empty body in that case, not QUIT) and deadlocks caused by sending packets outside the tcp window size.

=item -tls

Require connection to use STARTTLS.  Exit if TLS not available for any reason (not advertised, negotiations failed, etc).

=item -tlso, --tls-optional

Attempt to use STARTTLS if possible, continue t/ normal transaction if TLS unavailable.

=item -tlsc, --tls-on-connect

Initiate a TLS connection immediately on connection.  Use to test smtps/ssmtp servers.  If this options is specified, the default port changes from 25 to 465, though this can still be overridden with the -p option.

=item -a, --auth

Require authentication.  If Authentication fails or is unavailable, stop transaction.  -a can take an argument specifying which type(s) of authentication to try.  If multiple, comma-delimited arguments are given, each specified auth type is tried in order until one succeeds or they all fail.  swaks currently supports PLAIN, LOGIN, and CRAM-MD5.  If no argument is given any available authentication type is used.  If neither password (-ap) or username (-au) is supplied on command line, swaks will prompt on STDIN.

SPA (NTLM/MSN) authentication is now supported.  Tested as a client against Exim and Stalker's CommuniGate, but implementation may be incomplete.  Authen::NTLM is currently required.  Note that CPAN hosts two different Authen::NTLM modules.  Current implementation requires Mark Bush's implementation (Authen/NTLM-1.02.tar.gz).  Plan to reimplement directly at some point to avoid confusion.

DIGEST-MD5 is now supported.  Tested as a client only against Stalker's Communigate, so implementation may be incomplete.  Requires Authen::DigestMD5 module.

CRAM-SHA1 is now supported.  Only tested against a hacked server implementation in Exim, so may be incomplete or incorrect.  Requires Digest::SHA1 module.

=item -ao, --auth-optional

Same as -a, but if authentication is unavailable or fails, attempts to continue transaction.

=item -au, --auth-user

Supply the username for authentication.  The string <> can be supplied to mean an empty username.

For SPA authentication, a "domain" can be specified after the regular username with a % seperator.  For instance, if "-ap user@example.com%NTDOM" is passed, "user@example.com" is the username and "NTDOM" is the domain.  NOTE: I don't actually have access to a mail server where the domain isn't ignored, so this may be implemented incorrectly.

=item -ap, --auth-password

Supply the password for authentication.  The string <> can be supplied to mean an empty password.

=item -am --auth-map

Provides a way to map alternate names onto base authentication types.  Useful for any sites that use alternate names for common types.  This functionality is actually used internally to map types SPA and MSN onto the base type NTLM.  The command line argument to simulate this would be "--auth-map SPA=NTLM,MSN=NTLM".  The base types supported are LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5, and NTLM.  SPA and MSN are mapped on to NTLM automatically.

=item -apt, --auth-plaintext

Instead of showing AUTH strings literally (in base64), translate them to plaintext before printing on screen.

=item -nth, --no-hints

Don't show transaction hints.  (Useful in conjunction with -hr to create copy/paste-able transactions

=item -hr, --hide-receive

Don't display reception lines

=item -hs, --hide-send

Don't display sending lines

=item -stl, --show-time-lapse

Display time lapse between send/receive pairs.  If 'i' is provided as argument or the Time::HiRes module is unavailable the time lapse will be integer only, otherwise it will be to the thousandth of a second.

=item --force-getpwuid

In releases 20050709.1 and earlier of swaks the local_part of an automatically generated sender email address would be found using the getpwuid system call on the euid of the current process.  Depending on the users' desires, this may be confusing.  Following the 20050709.1 release the local_part is not looked up via the getlogin() funtion which attempts to look up the actual username of the logged in user, regardless of the euid of the process they are currently running.

An example of where this might be an issue is running swaks under sudo for testing reasons when interacting with --pipe or --socket.  It makes sense that you need to run the process as a specific username but you would prefer your email to be from your real username.  You could always do this manually using the -s option, but this is an attempt to make it easier.

--force-getpwuid forces the old behaviour for anyone who prefered that behaviour.  Also, if there is no "real" user for getlogin() to look up, the old getpwuid method will be used.  This would happen if the process was run from cron or some other headless daemon.

=item --help

This screen.

=item --version

Version info.

=back

=head1 EXAMPLES

=over 4

=item swaks

prompt user for to address and send a default email.

=item cat mailfile | swaks -g -n -t user@example.com -tlso -a -au user -ap password

send the contents of "mailfile" to user@example.com, using TLS if available, requiring authentication, using user/password as authentication information.

=back

=head1 COMMENTS

This program was written because I was testing a new MTA on an alternate port.  I did so much testing that using interactive telnet grew tiresome.  Over the next several years this program was fleshed out and every single option was added as a direct need of some testing I was doing as the mail admin of a medium sized ISP, with the exception of TLS support which was added on a whim.  As such, all options are reasonably well thought out and fairly well tested (though TLS could use more testing).

=head1 REQUIRES

swaks does not have any single requirement except the standard module Getopt::Long.  However, there may be modules that are required for a given invocation of swaks.  The following list details the features reported by the --support option, what is actually being tested, and the consequences of the feature being reported as "not available"

=over 4

=item AUTH CRAM-MD5

CRAM-MD5 authentication requires the Digest::MD5 perl module.  If this is unavailable and authentication is required, swaks will error if CRAM-MD5 was the specific authentication type requested, or if no specific auth type was requested but CRAM-MD5 was the only type advertised by the server.

=item AUTH CRAM-SHA1

CRAM-SHA1 authentication requires the Digest::SHA1 perl module.  If this is unavailable and authentication is required, swaks will error if CRAM-SHA1 was the specific authentication type requested, or if no specific auth type was requested but CRAM-SHA1 was the only type advertised by the server.

=item AUTH DIGEST-MD5

DIGEST-MD5 authentication requires the Authen::DigestMD5 perl module.  If this is unavailable and authentication is required, swaks will error if DIGEST-MD5 was the specific authentication type requested, or if no specific auth type was requested but DIGEST-MD5 was the only type advertised by the server.

=item AUTH NTLM

NTLM/SPA/MSN authentication requires the Authen::NTLM perl module.  If this is unavailable and authentication is required, swaks will error if NTLM was the specific authentication type requested, or if no specific auth type was requested but NTLM was the only type advertised by the server.  Note that there are two modules using the Authen::NTLM namespace on CPAN.  The Mark Bush implementation (Authen/NTLM-1.02.tar.gz) is the version required here.

=item Basic AUTH

All authentication types require base64 encoding and decoding.  If possible, swaks uses the MIME::Base64 perl module to perform these actions.  However, if MIME::Base64 is not available swaks will use its own onboard base64 routines.  These are slower than the MIME::Base64 routines and less reviewed, though they have been tested thoroughly.  When possible it is recommended that you install MIME::Base64.

=item Date Manipulation

swaks generates an RFC compliant date string when it interpolates the %D token in message bodies.  In order to build the GMT offset in this string, it needs the Time::Local module.  It would be very odd for this module not to be available because it has been included in the perl distribution for some time.  However, if it is not loadable for some reason and swaks interpolates a %D token (as it would when using the default body), the date string is in GMT instead of your local timezone.

=item High Resolution Timing

When diagnosing SMTP delays using --show-time-lapse, by default high resolution timing is attempted using the Time::HiRes module.  If this module is not available, swaks uses a much poorer timing source with one second granularity.

=item Local Hostname Detection

swaks uses your local machine's hostname to build the HELO string and sending email address when they are not specified on the command line.  If the Sys::Hostname module (which is a part of the base distribution) is not available for some reason, the user is prompted interactively for the HELO and sender strings.  Note that Sys::Hostname can sometimes fail to find the local hostname even when the module is available, which has the same behaviour.

=item MX Routing

If the destination mail server is not specified using the --server option, swaks attempts to use DNS to route the message based on the recipient email address.  If the Net::DNS perl module is not available, swaks uses 'localhost' as the outbound mail server.

=item Pipe Transport

The IPC::Open2 module is required to deliver a message to a spawned subprocess using the --pipe option.  If this module, which is included in the base perl distribution, in not available, attempting to call swaks with the --pipe option will result in an error.

=item Socket Transport

The IO::Socket module is required to deliver a message to an internet domain socket (the default behaviour of swaks) and to a unix domain socket (specified with the --socket option).  If this module, which is included in the base perl distribution, is not available, attempting to call swaks with the --server or --socket options (or none of the --socket, --server, and --pipe options) will result in an error.

=item TLS

TLS functionality requires the Net::SSLeay perl module.  If this module is not available and TLS was required (using the --tls-on-connect or --tls options), the session will error out.  If TLS was requested but not required (using the --tls-optional option), swaks will continue but not attempt a TLS session.

=back

=head1 PORTABILITY

=over 4

=item Operating Systems

This program was primarily intended for use on unix-like operating systems, and it should work on any reasonable version thereof.  It has been developed and tested on Solaris, Linux, and Mac OS X and is feature complete on all of these.

This program is known to demonstrate basic functionality on Windows using ActiveState's Perl.  It has not been fully tested.  Known to work are basic SMTP functionality and the LOGIN, PLAIN, and CRAM-MD5 auth types.  Unknown is any TLS functionality and the NTLM/SPA and Digest-MD5 auth types.

Because this program should work anywhere Perl works, I would appreciate knowing about any new operating systems you've thoroughly used swaks on as well as any problems encountered on a new OS.

=item Mail Servers

This program was almost exclusively developed against Exim mail servers.  It was been used casually by the author, though not thoroughly tested, with sendmail, smail, and Communigate.  Because all functionality in swaks is based off of known standards it should work with any fairly modern mail server.  If a problem is found, please alert the author at the address below.

=back

=head1 EXIT CODES

=over 4

=item 0

no errors occurred

=item 1

error parsing command line options

=item 2

error connecting to remote server

=item 3

unknown connection type

=item 4

while running with connection type of "pipe", fatal problem writing to or reading from the child process

=item 5

while running with connection type of "pipe", child process died unexpectedly.  This can mean that the program specified with --pipe doesn't exist.

=item 6

Connection closed unexpectedly.  If the close is detected in response to the 'QUIT' swaks sends following an unexpected response, the error code for that unexpected response is used instead.

For instance, if a mail server returns a 550 response to a MAIL FROM: and then immediately closes the connection, swaks detects that the connection is closed, but uses the more specific exit code 23 to detail the nature of the failure.

If instead the server return a 250 code and then immediately closes the connection, swaks will use the exit code 6 because there is not a more specific exit code.

=item 10

error in prerequisites (needed module not available)

=item 21

error reading initial banner from server

=item 22

error in HELO transaction

=item 23

error in MAIL transaction

=item 24

no RCPTs accepted

=item 25

server returned error to DATA request

=item 26

server did not accept mail following data

=item 27

server returned error after normal-session quit request

=item 28

error in AUTH transaction

=item 29

error in TLS transaction

=item 32

error in EHLO following TLS negotiation

=back

=head1 CONTACT

=over 4

=item proj-swaks@jetmore.net

Please use this address for general contact, questions, patches, requests, etc.

=item updates-swaks@jetmore.net

If you would like to be put on a list to receive notifications when a new version of swaks is released, please send an email to this address.

=item jetmore.org/john/code/#swaks

Change logs, this help, and the latest version is found at this link.

=back

=cut

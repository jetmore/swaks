#!/usr/bin/env perl

# add tls support for all domains

# ./smtp-server.pl -p 8026 scripts/basic-successful-email.txt
# ./swaks -s 127.0.0.1 -p 8026 -t foo@example.com



# ./smtp-server -p 8026 -i 127.0.0.1 -d inet
# swaks -s 127.0.0.1 -p 8026

# ./smtp-server -i /tmp/foo.s -d unix
# swaks --socket /tmp/foo.s

# swaks --pipe './smtp-server.pl -d pipe'


use strict;
no strict "subs";
use Socket;
use IO::Socket::IP;
use Getopt::Long;
use Net::SSLeay qw(die_now die_if_ssl_error);
use FindBin qw($Bin);

my %opt     = ();
GetOptions(\%opt, 'port|p=s', 'interface|i=s', 'domain|d=s', 'silent|s!', 'include=s@', 'cert=s', 'key=s', 'cafile=s') || mexit(1);
# p - port
# i - interface (or socket file for unix domain)
# d - domain (inet or unix or pipe)
# s - silent (don't print transaction hints)
# include files - if specified even once, no command line file will be checked.  If multiple, will be executed in order specified

my $scriptDir   = "$Bin/scripts";
my @scriptFiles = ();
if (exists($opt{include}) && ref($opt{include}) eq 'ARRAY') {
  @scriptFiles = @{$opt{include}};
}
elsif (scalar(@ARGV)) {
  @scriptFiles = @ARGV;
}
else {
  @scriptFiles = ($scriptDir . '/script-basic-success.txt');
}

for (my $i = 0; $i < @scriptFiles; $i++) {
  my($file, @tokens) = split(/::/, $scriptFiles[$i]);
  if ($file !~ m%[/\\]%) {
    $file = "$scriptDir/$file";
  }

  if (!-f $file) {
    mexit(1, "script file $file does not exist\n");
  }

  my $info = {
    file => $file,
    tokens => {},
  };
  for (my $j = 0; $j < @tokens; $j++) {
    my $token = $tokens[$j];
    my $value = $tokens[++$j];
    $value =~ s/([^\\])([\@\$\%])/$1\\$2/g; # not a huge fan of this, but since we're eval'ing this, protect perl sigils
    $info->{tokens}{$token} = $value;
  }
  $scriptFiles[$i] = $info;
}

my $keyFile  = $opt{key}    || $Bin . '/../certs/node.example.com.key';
my $certFile = $opt{cert}   || $Bin . '/../certs/node.example.com.crt';
my $caFile   = $opt{cafile} || "";

my $domain  = lc($opt{domain}) || 'inet';
if ($domain !~ /^(unix|inet|pipe)$/) {
  mexit(1, "unknown domain $domain\n");
}
my %cxn     = ();
my $port    = $opt{port} || 11111;
my $lint    = $domain eq 'unix' ? $opt{interface} || "/tmp/server.$>.$$" : $opt{interface} || '0.0.0.0';

open(L, ">&STDERR") || warn "Can't redirect L: $!\n";
select((select(L), $| = 1)[0]);

get_cxn(set_up_cxn($domain, $lint, $port));

foreach my $scriptFile (@scriptFiles) {
  handle_script_file($scriptFile);
}

exit;

sub handle_script_file {
  my $args = shift;
  my $file = ref($args) ? $args->{file} : $args;

  print "Run script file $file\n" if (!$opt{silent});
  open(my $fh, "<$file") || die "Can't open $file: $!\n";
  while (defined(my $l = <$fh>)) {
    if ($l =~ /^include\(['"](?:\$scriptDir\/)?(.*)['"]\);/) {
      handle_script_file($scriptDir . '/' . $1);
    }
    else {
      if (ref($args)) {
        foreach my $token (keys %{$args->{tokens}}) {
          $l =~ s|\.\.$token\.\.|$args->{tokens}{$token}|g
        }
      }

      eval($l);
      if ($@) {
        chomp($@);
        print STDERR "error occurred in line $l: $@\n";
      }
    }
  }
  close($fh);
}

sub get_cxn {
  my $s = shift;

  if ($s) {
    $cxn{cxn} = $s->accept();
    $cxn{type} = "socket";
    if ($domain eq 'inet') {
      $cxn{peer}{addr} = Socket::inet_ntop(length($cxn{cxn}->peeraddr()) == 4 ? AF_INET : AF_INET6, $cxn{cxn}->peeraddr());
      $cxn{peer}{port} = $cxn{cxn}->peerport();
    }
  } else {
    $cxn{cxn_wr} = \*STDOUT;
    $cxn{cxn_re} = \*STDIN;
    select((select($cxn{cxn_wr}), $| = 1)[0]);
    select((select($cxn{cxn_re}), $| = 1)[0]);
    $cxn{type} = "pipe";
  }
  $cxn{tls}{active} = 0;
}

sub print_tls_info {
  foreach my $part (@_) {
    if ($part eq 'protocol') {
      print L "220-TLS Protocol Version: $cxn{tls}{version_string}\n";
    }
    elsif ($part eq 'cipher') {
      print L "220-TLS Cipher: $cxn{tls}{cipher}\n";
    }
    elsif ($part eq 'peercert') {
      print L "220-TLS Peer Certificate Subject: $cxn{tls}{peer_cert_subject}\n";
    }
    elsif ($part eq 'snistring') {
      print L "220-TLS SNI String: $cxn{tls}{sni_string}\n";
    }
  }
}

sub set_up_cxn {
  my $domain = shift; # inet or unix
  my $lint   = shift; # sockfile for unix, ip:port for inet
  my $port   = shift;
  my $server;

  return if ($domain eq 'pipe');

  if ($domain eq 'unix') {
    unlink($lint);
    mexit(4, "socket file $lint exists, refusing to proceed") if (-e $lint);
    if (!($server = IO::Socket::UNIX->new(Local => $lint, Listen => SOMAXCONN, Type => SOCK_STREAM))) {
      warn("Couldn't be a unix domain server on $lint: $@");
      exit(2);
    }
    print L "listening on $lint pid $$\n" if (!$opt{silent});
  } else {
    if (!($server = IO::Socket::IP->new(Proto => 'tcp', Listen => SOMAXCONN, ReuseAddr => 1, LocalAddr => $lint, LocalPort => $port))) {
      mexit(2, "Couldn't be an inet domain server on $lint($port): $@");
    }
    print L "listening on $lint($port) pid $$\n" if (!$opt{silent});
  }
  return($server);
}

sub mexit {
  my $exit = shift || 11;
  my $msg  = shift || "mistake occurred";

  print STDERR "$msg\n";
  exit($exit);
}

sub send_line {
  my $l = shift;
  print L "> $l\n" if (!$opt{silent});
  $l =~ s/([^\r])\n/$1\r\n/;

  if ($cxn{tls}{active}) {
    Net::SSLeay::write($cxn{tls}{ssl}, "$l\r\n");
  } else {
    my $s = $cxn{type} eq 'pipe' ? $cxn{cxn_wr} : $cxn{cxn};
    print $s $l, "\r\n";
  }

  return;
}

sub get_line {
  my $e = shift; # regexp we are looking for.  read until we find it, or return after first line if empty
  my $r;
  my $l;

  my $s = $cxn{type} eq 'pipe' ? $cxn{cxn_re} : $cxn{cxn};

  do {
    if ($cxn{tls}{active}) {
      $l = Net::SSLeay::read($cxn{tls}{ssl});
    } else {
      $l = <$s>;
    }
    $l =~ s/\r//g;
    print L "< $l" if (!$opt{silent});
    $r .= $l;
  } while ($e && $l && $l !~ /$e/ms);

  return($r);
}

sub start_tls {
  my $opts      = shift || {};
  $Net::SSLeay::trace = 9;
  my $ssl_keyf  = $keyFile;
  my $ssl_certf = $certFile;
  my $ssl_caf   = $caFile;

  Net::SSLeay::load_error_strings();
  Net::SSLeay::SSLeay_add_ssl_algorithms();
  Net::SSLeay::randomize();
  $cxn{tls}{ctx} = Net::SSLeay::CTX_new();
  Net::SSLeay::CTX_set_options($cxn{tls}{ctx}, &Net::SSLeay::OP_ALL);
  Net::SSLeay::CTX_use_RSAPrivateKey_file ($cxn{tls}{ctx}, $ssl_keyf, &Net::SSLeay::FILETYPE_PEM);
  Net::SSLeay::CTX_use_certificate_file ($cxn{tls}{ctx}, $ssl_certf, &Net::SSLeay::FILETYPE_PEM);
  Net::SSLeay::CTX_set_tlsext_servername_callback($cxn{tls}{ctx}, sub { $cxn{tls}{sni_string} = Net::SSLeay::get_servername(shift()); });

  # https://stackoverflow.com/questions/21050366/testing-ssl-tls-client-authentication-with-openssl
  if ($opts->{VERIFY_PEER}) {
    Net::SSLeay::CTX_load_verify_locations($cxn{tls}{ctx}, $ssl_caf, '');
    Net::SSLeay::CTX_set_verify($cxn{tls}{ctx}, &Net::SSLeay::VERIFY_PEER, \&verify);
  }

  $cxn{tls}{ssl} = Net::SSLeay::new($cxn{tls}{ctx});

  if ($cxn{type} eq 'pipe') {
    Net::SSLeay::set_rfd($cxn{tls}{ssl}, fileno($cxn{cxn_re}));
    Net::SSLeay::set_wfd($cxn{tls}{ssl}, fileno($cxn{cxn_wr}));
  } else {
    Net::SSLeay::set_fd($cxn{tls}{ssl}, fileno($cxn{cxn}));
  }
  my $err = Net::SSLeay::accept($cxn{tls}{ssl}) ;
  # print "err in TLS accept: $err\n" if ($err);
  $cxn{tls}{active}            = 1;
  $cxn{tls}{version}           = Net::SSLeay::version($cxn{tls}{ssl});
  eval {
    $cxn{tls}{version_name}      = Net::SSLeay::get_version($cxn{tls}{ssl}); # 1.85 doesn't have this, 1.88 does
  };
  if ($@) {
    # can hard code other version -> name mappings here if I need them
    if ($cxn{tls}{version} == 0x0303) {
      $cxn{tls}{version_name} = 'TLSv1.2';
    }
    elsif ($cxn{tls}{version} == 0x0304) {
      $cxn{tls}{version_name} = 'TLSv1.3';
    }
  }
  $cxn{tls}{version_string}     = sprintf("0x%04x/%s", $cxn{tls}{version}, $cxn{tls}{version_name});
  $cxn{tls}{cipher}             = Net::SSLeay::get_cipher($cxn{tls}{ssl});
  $cxn{tls}{sni_string}       ||= "No SNI string present";
  $cxn{tls}{peer_cert}          = Net::SSLeay::get_peer_certificate($cxn{tls}{ssl});
  $cxn{tls}{peer_certs}         = [ Net::SSLeay::get_peer_cert_chain($cxn{tls}{ssl}) ];

  $cxn{tls}{peer_cert_subject}  = "No client certificate present";
  $cxn{tls}{peer_cert_subjects} = [];

  if ($cxn{tls}{peer_cert}) {
    $cxn{tls}{peer_cert_subject} = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($cxn{tls}{peer_cert}));
    push(@{$cxn{tls}{peer_cert_subjects}}, $cxn{tls}{peer_cert_subject});
  }

  if ($cxn{tls}{peer_certs} && scalar(@{$cxn{tls}{peer_certs}})) {
    foreach my $cert (@{$cxn{tls}{peer_certs}}) {
      push(@{$cxn{tls}{peer_cert_subjects}}, Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($cert)));
    }
  }

  print L "* Cipher '$cxn{tls}{cipher}'\n" if (!$opt{silent});
}

sub show_tls_info {
  #250-TLS peer DN=/C=US/ST=Indiana/O=Swaks Development (unsigned.example.com, with-SAN)/CN=unsigned.example.com/emailAddress=proj-swaks@jetmore.net
    if ($cxn{tls}{peer_cert_subjects} && scalar(@{$cxn{tls}{peer_cert_subjects}})) {
      for (my $i = 0; $i < scalar(@{$cxn{tls}{peer_cert_subjects}}); $i++) {
        my $subject = $cxn{tls}{peer_cert_subjects}[$i];
        send_line("250-TLS peer $i DN=$subject");
      }
    }
    else {
      send_line("250-TLS peer DN=No client certificate present");
    }
}


sub verify {
  return 1; # 0 means ok
}

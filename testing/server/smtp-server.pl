#!/usr/bin/perl

# add tls support for all domains

use strict;
use IO::Socket;
use Getopt::Std;
use Net::SSLeay;

my %opt     = ();
getopts('t:p:i:d:f:s', \%opt) || mexit(1);
# p - port
# i - interface (or socket file for unix domain)
# d - domain (inet or unix or pipe)
# s - silent (don't print transaction hints
# f - script file to use

my $domain  = lc($opt{d}) || 'inet';
if ($domain !~ /^(unix|inet|pipe)$/) {
  print STDERR "unknown domain $domain\n";
  exit;
}
my $port    = $opt{p} || 11111;
my $lint    = $domain eq 'unix'
                ? $opt{i} || "/tmp/server.$>.$$"
                : $opt{i} || '0.0.0.0';
$lint      .= ":$port" if ($domain eq 'inet' && $lint !~ /:/);
my %cxn = ();
  

open(L, ">&STDERR") || warn "Can't redirect L: $!\n";
select((select(L), $| = 1)[0]);

get_cxn(set_up_cxn($domain, $lint));

if ($opt{f}) {
  handle_script_file($opt{f});
} else {
  handle_session();
}

exit;

sub handle_script_file {
  my $f = shift;
  open(I, "<$f") || die "Can't open $f: $!\n";
  while (defined(my $l = <I>)) {
    eval($l);
  }
  close(I);
}

sub get_cxn {
  my $s = shift;

  if ($s) {
    $cxn{cxn} = $s->accept();
    $cxn{type} = "socket";
  } else {
    $cxn{cxn_wr} = \*STDOUT;
    $cxn{cxn_re} = \*STDIN;
    select((select($cxn{cxn_wr}), $| = 1)[0]);
    select((select($cxn{cxn_re}), $| = 1)[0]);
    $cxn{type} = "pipe";
  }
  $cxn{tls}{active} = 0;
}

sub handle_session {

  #start_tls(); # this is for tls_on_connect

  #print L "connection received\n";
  send_line("220 SERVER ESMTP ready");

  # uncomment this to force fallback to HELO
  #get_line(); #EHLO
  #send_line("500 unrecognized");

  get_line(); # EHLO
  #send_line("250-SERVER Hello Server [1.1.1.1]\n250-STARTTLS\n205-AUTH DIGEST-MD5\n250-AUTH=login\n250 HELP");
  #send_line("250-SERVER Hello Server [1.1.1.1]\n250-STARTTLS\n205-AUTH DIGEST-MD5\n250 HELP");
  send_line("250-SERVER Hello Server [1.1.1.1]");
  send_line("250-STARTTLS");
  #send_line("250-AUTH CRAM-MD5");
  #send_line("250-AUTH PLAIN");
  send_line("250-AUTH DIGEST-MD5");
  #send_line("250-AUTH=login");
  send_line("250 HELP");

  #get_line(); # STARTTLS
  #send_line("220 TLS go ahead");
  #start_tls();
  #get_line(); # EHLO
  #send_line("250-SERVER Hello Server [1.1.1.1]\n250 HELP");

  get_line(); # AUTH DIGEST-MD5
  send_line("334 bm9uY2U9IlFpdERwa1BFN2VXS0pYUytDdnFCNWFlajkrcCtpa2dWN2hOQVFOZThTMlU9IixyZWFsbT0ibGFwcHkuamV0bW9yZS5uZXQiLHFvcD0iYXV0aCxhdXRoLWludCxhdXRoLWNvbmYiLGNpcGhlcj0icmM0LTQwLHJjNC01NixyYzQsZGVzLDNkZXMiLG1heGJ1Zj04MTkyLGNoYXJzZXQ9dXRmLTgsYWxnb3JpdGhtPW1kNS1zZXNz");
  #send_line("334 bm9uY2U9Ijk0Mjk4NWExMTY3NzA1NDQ1YXZtLnFzZXJ2ZXJzeXN0ZW1zLmNvbSIscW9wPSJhdXRoIixhbGdvcml0aG09bWQ1LXNlc3M=");
  get_line(); # AUTH DIGEST-MD5 digest
  send_line("334 cnNwYXV0aD1mYjI2NjZlOGM3YWJiNTllM2M1ZWI1ZDU0Y2VjMjc3Zg==");
  get_line(); # AUTH DIGEST-MD5 digest
  send_line("235 Authentication succeeded");

  #get_line(); # AUTH PLAIN
  #send_line("235 Authentication succeeded");

  #get_line(); # AUTH LOGIN
  #send_line("334 VXNlcm5hbWU6");
  #get_line(); # AUTH LOGIN username
  #send_line("334 UGFzc3dvcmQ6");
  #get_line(); # AUTH LOGIN password
  #send_line("235 Authentication succeeded");

  get_line(); # MAIL
  send_line("250 Accepted");

  get_line(); # RCPT
  send_line("250 Accepted");

  get_line(); # DATA (command, not actual data)
  send_line("354 Enter message, ending with \".\" on a line by itself");

  get_line('^\.$'); # rest of email
  send_line("250 OK id=fakeemail");

  get_line();
  send_line("221 SERVER closing connection");
}

sub set_up_cxn {
  my $domain = shift; # inet or unix
  return if ($domain eq 'pipe');
  my $lint   = shift; # sockfile for unix, ip:port for inet
  my $server;

  if ($domain eq 'unix') {
    unlink($lint);
    mexit(4, "socket file $lint exists, refusing to proceed") if (-e $lint);
    if (!($server = IO::Socket::UNIX->new(Local => $lint, Listen => SOMAXCONN,
                                          Type => SOCK_STREAM)))
    {
      warn("Couldn't be a unix domain server on $lint: $@");
      exit(2);
    }
    print L "listening on $lint pid $$\n";
  } else {
    if (!($server = IO::Socket::INET->new(Proto => 'tcp', Listen => SOMAXCONN,
                                          ReuseAddr => 1,
                                          LocalAddr => $lint)))
    {
      mexit(2, "Couldn't be an inet domain server on $lint: $@");
    }
    print L "listening on $lint pid $$\n";
  }
  return($server);
}

sub mexit {
  my $exit = shift || 11;
  my $msg  = shift || "mistake occurred";

  print STDERR "$msg\n";
  exit($exit);
}

sub test {
  print (join(', ', @_), "\n");
}

sub send_line {
  my $l = shift;
  print L "> $l\n" if (!$opt{s});
  $l =~ s/([^\r])\n/$1\r\n/;

  if ($cxn{tls}{active}) {
    Net::SSLeay::write($cxn{tls}{ssl}, "$l\r\n");
  } else {
    my $s = $cxn{cxn};
    $s = $cxn{cxn_wr} if ($cxn{type} eq 'pipe');
    print $s $l, "\r\n";
  }

  return;
}

sub get_line {
  my $e = shift; # regexp we are looking for.  read until we find it, or
                 # return after first line if empty
  my $r;
  my $l;

  my $s = $cxn{cxn};
  $s = $cxn{cxn_re} if ($cxn{type} eq 'pipe');
    

  do {
    if ($cxn{tls}{active}) {
      $l = Net::SSLeay::read($cxn{tls}{ssl});
    } else {
      $l = <$s>;
    }
    $l =~ s/\r//g;
    print L "< $l" if (!$opt{s});
    $r .= $l;
  } while ($e && $l && $l !~ /$e/ms);

  return($r);
}

sub start_tls {

  $Net::SSLeay::trace = 9;
  my $ssl_keyf = '/home/jetmore/Documents/programming/swaks/misc-tools/ssl-private-key';
  my $ssl_certf = '/home/jetmore/Documents/programming/swaks/misc-tools/ssl-public-key';

  Net::SSLeay::load_error_strings();
  Net::SSLeay::SSLeay_add_ssl_algorithms();
  Net::SSLeay::randomize();
  $cxn{tls}{ctx} = Net::SSLeay::CTX_new();
  Net::SSLeay::CTX_set_options($cxn{tls}{ctx}, &Net::SSLeay::OP_ALL);
  Net::SSLeay::CTX_use_RSAPrivateKey_file ($cxn{tls}{ctx}, $ssl_keyf,
                                                 &Net::SSLeay::FILETYPE_PEM);
  Net::SSLeay::CTX_use_certificate_file ($cxn{tls}{ctx}, $ssl_certf,
                                               &Net::SSLeay::FILETYPE_PEM);

  $cxn{tls}{ssl} = Net::SSLeay::new($cxn{tls}{ctx});
  if ($cxn{type} eq 'pipe') {
    Net::SSLeay::set_rfd($cxn{tls}{ssl}, fileno($cxn{cxn_re}));
    Net::SSLeay::set_wfd($cxn{tls}{ssl}, fileno($cxn{cxn_wr}));
  } else {
    Net::SSLeay::set_fd($cxn{tls}{ssl}, fileno($cxn{cxn}));
  }
  my $err = Net::SSLeay::accept($cxn{tls}{ssl}) ;
  print L "* Cipher '", Net::SSLeay::get_cipher($cxn{tls}{ssl}), "'\n"
      if (!$opt{s});
  $cxn{tls}{active} = 1;
}

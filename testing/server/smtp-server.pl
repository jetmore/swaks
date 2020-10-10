#!/usr/bin/perl

# add tls support for all domains

# ./smtp-server.pl -p 8026 scripts/basic-successful-email.txt
# ./swaks -s 127.0.0.1 -p 8026 -t foo@example.com



# ./smtp-server -p 8026 -i 127.0.0.1 -d inet
# swaks -s 127.0.0.1 -p 8026

# ./smtp-server -i /tmp/foo.s -d unix
# swaks --socket /tmp/foo.s

# swaks --pipe './smtp-server.pl -d pipe'


use strict;
use IO::Socket;
use Getopt::Std;
use Net::SSLeay;
use FindBin qw($Bin);

my %opt     = ();
getopts('t:p:i:d:f:s', \%opt) || mexit(1);
# p - port
# i - interface (or socket file for unix domain)
# d - domain (inet or unix or pipe)
# s - silent (don't print transaction hints)

my $scriptFile = shift;
if (!$scriptFile) {
  $scriptFile = $Bin . '/scripts/basic-successful-email.txt';
}
if (!-f $scriptFile) {
  mexit(1, "script file $scriptFile does not exist\n");
}

my $domain  = lc($opt{d}) || 'inet';
if ($domain !~ /^(unix|inet|pipe)$/) {
  mexit(1, "unknown domain $domain\n");
}
my $port    = $opt{p} || 11111;
my $lint    = $domain eq 'unix' ? $opt{i} || "/tmp/server.$>.$$" : $opt{i} || '0.0.0.0';
$lint      .= ":$port" if ($domain eq 'inet' && $lint !~ /:/);
my %cxn     = ();

open(L, ">&STDERR") || warn "Can't redirect L: $!\n";
select((select(L), $| = 1)[0]);

get_cxn(set_up_cxn($domain, $lint));

handle_script_file($scriptFile);

exit;

sub handle_script_file {
  my $f = shift;
  print "Run script file $f\n";
  open(my $fh, "<$f") || die "Can't open $f: $!\n";
  while (defined(my $l = <$fh>)) {
    if ($l =~ /^include\(['"](?:\$Bin\/)?(.*)['"]\);/) {
      handle_script_file($Bin . '/' . $1);
    }
    else {
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
  } else {
    $cxn{cxn_wr} = \*STDOUT;
    $cxn{cxn_re} = \*STDIN;
    select((select($cxn{cxn_wr}), $| = 1)[0]);
    select((select($cxn{cxn_re}), $| = 1)[0]);
    $cxn{type} = "pipe";
  }
  $cxn{tls}{active} = 0;
}

sub set_up_cxn {
  my $domain = shift; # inet or unix
  return if ($domain eq 'pipe');
  my $lint   = shift; # sockfile for unix, ip:port for inet
  my $server;

  if ($domain eq 'unix') {
    unlink($lint);
    mexit(4, "socket file $lint exists, refusing to proceed") if (-e $lint);
    if (!($server = IO::Socket::UNIX->new(Local => $lint, Listen => SOMAXCONN, Type => SOCK_STREAM))) {
      warn("Couldn't be a unix domain server on $lint: $@");
      exit(2);
    }
    print L "listening on $lint pid $$\n";
  } else {
    if (!($server = IO::Socket::INET->new(Proto => 'tcp', Listen => SOMAXCONN, ReuseAddr => 1, LocalAddr => $lint))) {
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

sub send_line {
  my $l = shift;
  print L "> $l\n" if (!$opt{s});
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
    print L "< $l" if (!$opt{s});
    $r .= $l;
  } while ($e && $l && $l !~ /$e/ms);

  return($r);
}

sub start_tls {
  $Net::SSLeay::trace = 9;
  my $ssl_keyf  = $Bin . '/test.key';
  my $ssl_certf = $Bin . '/test.crt';

  Net::SSLeay::load_error_strings();
  Net::SSLeay::SSLeay_add_ssl_algorithms();
  Net::SSLeay::randomize();
  $cxn{tls}{ctx} = Net::SSLeay::CTX_new();
  Net::SSLeay::CTX_set_options($cxn{tls}{ctx}, &Net::SSLeay::OP_ALL);
  Net::SSLeay::CTX_use_RSAPrivateKey_file ($cxn{tls}{ctx}, $ssl_keyf, &Net::SSLeay::FILETYPE_PEM);
  Net::SSLeay::CTX_use_certificate_file ($cxn{tls}{ctx}, $ssl_certf, &Net::SSLeay::FILETYPE_PEM);

  $cxn{tls}{ssl} = Net::SSLeay::new($cxn{tls}{ctx});
  if ($cxn{type} eq 'pipe') {
    Net::SSLeay::set_rfd($cxn{tls}{ssl}, fileno($cxn{cxn_re}));
    Net::SSLeay::set_wfd($cxn{tls}{ssl}, fileno($cxn{cxn_wr}));
  } else {
    Net::SSLeay::set_fd($cxn{tls}{ssl}, fileno($cxn{cxn}));
  }
  my $err = Net::SSLeay::accept($cxn{tls}{ssl}) ;
  print L "* Cipher '", Net::SSLeay::get_cipher($cxn{tls}{ssl}), "'\n" if (!$opt{s});
  $cxn{tls}{active} = 1;
}

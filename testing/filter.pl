#!/usr/bin/perl

use strict;
use IO::Socket;
use Getopt::Std;

my($p_name) = $0 =~ m|/?([^/]+)$|;
my $p_usage = "Usage: $p_name [--help] [-i<interface>] [-p<port>] [-t<proto>]";
ext_usage();

my %opt     = ();
getopts('t:p:i:d:', \%opt) || mexit(1);
# t - (t)ransport (udp or tcp) - sill be passed uncheck to IO::Socket
# p - port
# i - interface (or socket file for unix domain)
# d - domain (internet or unix)

my $domain  = lc($opt{d}) eq 'unix' ? 'unix' : 'internet';
my $proto   = lc($opt{t}) || 'udp';
my @listen  = ($proto eq 'tcp') ? ('Listen',SOMAXCONN) : ();
my $lint    = $domain eq 'unix'
                ? $opt{i} || "/tmp/server.$>.$$"
                : $opt{i} || '0.0.0.0';
my $MAXLEN  = 1024;
my $server  = undef;

my $port    = 11111;
if ($opt{p}) {
  if ($opt{p} =~ /^\d+$/) {
    $port = $opt{p};
  } else {
    if (!($port = (getservbyname($opt{p},$proto))[2])) {
      mexit(3, "unrecognized service ($opt{p})");
    }
  }
}

open(L, ">&STDOUT") || warn "Can't redirect L: $!\n";
select((select(L), $| = 1)[0]);

if ($domain eq 'unix') {
  mexit(4, "socket file $lint exists, refusing to proceed") if (-e $lint);
  #if (!($server = IO::Socket::UNIX->new(LocalAddr => $lint,
  #                Type => $proto eq 'udp' ? SOCK_DGRAM : SOCK_STREAM, @listen)))
  if (!($server = IO::Socket::UNIX->new(Local => $lint,
                  Type => $proto eq 'udp' ? SOCK_DGRAM : SOCK_STREAM)))
  {
    mexit(2, "Couldn't be a unix domain $proto server on $lint:$port: $@");
  }
  print L "$p_name listening on $lint, proto $proto, pid $$\n";
} else {
  if (!($server = IO::Socket::INET->new(LocalPort => $port,
                  Proto => $proto, LocalAddr => $lint, @listen)))
  {
    mexit(2, "Couldn't be an internet domain $proto server on $lint:$port: $@");
  }
  print L "$p_name listening on $lint:$port, proto $proto, pid $$\n";
}


if ($proto =~ /^tcp$/i) {
  handle_tcp($server);
} elsif ($proto =~ /^udp$/i) {
  handle_udp($server);
} else {
  mexit(4, "IO::Socket understands $proto but $p_name doesn't (yet)\n");
}

exit;

sub handle_tcp {
  my $s = shift; # server object
  my $c;
  my $r;
  
  my $out = IO::Socket::INET->new(Proto     => 'tcp',
                                    PeerPort  => 8025,
                                    PeerAddr  => '127.0.0.1')
          || die "Unable to contact remote host: $!\n";


  while ($c = $s->accept()) {
    my $in_ipaddr = $c->peeraddr;
    my $in_port   = $c->peerport;
    my $in_host   = gethostbyaddr($in_ipaddr, AF_INET);
    my $in_addr   = inet_ntoa($in_ipaddr);
    my $count = 0;
    print L "connection from $in_host($in_addr):$in_port\n";
    
    #LABEL:
    do {
      do {
        $r = <$out>;
        $count = 40 if (!$r);
        $r =~ s/[\n\r]//g;
        print L " -> $r\n";
        if ($r =~ /^334 / && length($r) < 80) {
          print L "altering rspauth string\n";
          $r =~ s/^(.{30})./${1}W/;
          print L " -> $r\n";
        }
        print $c "$r\n";
      } while ($r && $r !~ /^\d\d\d /);
    
      $r = <$c>;
      $r =~ s/[\n\r]//g;
      print L "<-  $r\n";
      print $out "$r\n";
    } while (++$count < 30);
    
    # while ($r = <$out>) {
    #   do {
    #   $r =~ s/[\n\r]//g;
    #   print L "got '$r' from server\n";
    #   #my $response  = "saw '$r' from $in_host($in_addr):$in_port";
    #   #print L "sent \"$response\" to $in_host\n";
    #   print $c "$r\n";

    #   $r = <$c>;
    #   $r =~ s/[\n\r]//g;
    #   print L "got '$r' from client\n";
    #   print $out "$r\n";
      
    # }
    print L "lost connection to $in_host\n";
  }
}

sub handle_udp {
  my $s = shift; # server object
  my $r;

  while ($s->recv($r, $MAXLEN)) {
    $r =~ s/[\n\r]//g;
   if ($domain eq 'unix') {
    #my $peer = $s->peerpath();
    print L "got '$r'\n";
    my $response  = "saw '$r'";
    $s->send($response);
   } else {
    my $in_ipaddr = $s->peeraddr;
    my $in_port   = $s->peerport;
    my $in_host   = gethostbyaddr($in_ipaddr, AF_INET);
    my $in_addr   = inet_ntoa($in_ipaddr);
    print L "got '$r' from $in_host\n";
    my $response  = "saw '$r' from $in_host($in_addr):$in_port";
    print L "sent \"$response\" to $in_host\n";
    $s->send($response);
   }
  }
}

exit;

sub mexit {
  my $exit = shift || 11;
  my $msg  = shift || $p_usage;

  print STDERR "$msg\n";
  exit($exit);
}

sub ext_usage {
  return if ($ARGV[0] !~ /^--help$/i);

  print "$p_usage\n\n";
  print "Set up a simple echo server\n",
        "Example: $p_name -t tcp -p 8080 -i 192.168.0.1\n",
        "\n",
        "Options:\n",
        "  -i\tlocal interface (defaults to all interfaces)\n",
	"  -t\tprotocol (udp by default)\n",
	"  -p\tlocal port (11111 by default)\n",
        "\n",
        "Examples:\n",
        "  $p_name\n",
        "\tset up a udp server listening on 0.0.0.0:11111\n",
	"  $p_name -t tcp -p 8080 -i 192.168.0.1\n",
	"\tset up a tcp server listening on 192.168.0.1:8080\n",
        "\n",
        "Exit Status:\n",
        "  0\tno errors occurred\n",
        "  1\terror parsing command line\n",
        "  2\tcouldn't instantiate IO::Socket object\n",
        "  3\tunknown service specified using -p\n",
        "  3\tunhandled protocol\n",
        "\n",
        "Contact:\n",
        "  elosoft-proj-server\@jetmore.net\n";
  exit(0);
}

sub test {
  print (join(', ', @_), "\n");
}

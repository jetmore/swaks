#!/usr/bin/perl

my $args;
open(I, "<$ARGV[0]") || die "Couldn't open $ARGV[0]\n";
while (<I>) {
	next if (!/sub get_option_struct/);
	while (<I>) {
		last if (/return\(@G::raw_option_data/);
		$args .= $_;
	}
	last;
}

eval $args;
# print $args;


# use Data::Dumper;

foreach my $o (@G::raw_option_data) {
	$okeys{$o->{okey}}++;
	map { $opts{$_}++; } (@{$o->{opts}});
}

foreach my $okey (keys %okeys) {
	print "Collision okey $okey $okeys->{$okey}\n" if ($okeys{$okey} > 1);
}
foreach my $opt (keys %opts) {
	print "Collision opts $opt $opts->{$opt}\n" if ($opts{$opt} > 1);
}

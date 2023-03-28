#!/usr/bin/env perl

# migrate.pl _options-data _options-data-new 0003 05000

my $odir = shift || die "Usage: migrate.pl old_dir new_dir old_test_num new_test_num\n";
my $ndir = shift || die "Usage: migrate.pl old_dir new_dir old_test_num new_test_num\n";
my $onum = shift || die "Usage: migrate.pl old_dir new_dir old_test_num new_test_num\n";
my $nnum = shift || die "Usage: migrate.pl old_dir new_dir old_test_num new_test_num\n";

if (!-f "$odir/$onum.test") {
	die "$odir/$onum.test doesn't exist\n";
}

if (!-d $ndir) {
	mkdir($ndir) || die "Couldn't mkdir($ndir)\n";
}
elsif (-f "$ndir/$nnum.test") {
	die "target test $ndir/$nnum.test already exists\n";
}

mkdir("$ndir/out-dyn") if (!-d "$ndir/out-dyn");
mkdir("$ndir/out-ref") if (!-d "$ndir/out-ref");

my @rename = ("$odir/$onum.test");
# push(@rename, "$odir/$onum.eml");

opendir(D, "$odir/out-ref") || die "Can't opendir $odir/out-ref: $!\n";
map { push(@rename, "$odir/out-ref/$_"); } (grep /^$onum\b/, readdir(D));
closedir(D);

foreach my $old (@rename) {
	my $new =  $old;
	$new    =~ s/\b$onum\b/$nnum/;
	$new    =~ s/\b$odir\b/$ndir/;

	print "$old -> $new\n";
	rename($old, $new) || warn "Can't rename($old, $new): $!\n";
}

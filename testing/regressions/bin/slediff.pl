#!/usr/bin/env perl

use strict;

use File::Spec::Functions qw(:ALL);
use Text::Diff qw();

# two ways to call this - the first is with two files and the second is with a dir and a testid.  Do our best to tell which is which
#
# slediff.pl _options-auth 00300.stdout
# slediff.pl _options-auth/out-ref/00300.stdout _options-auth/out-dyn/00300.stdout

my $testDir  = shift;
my $testFile = shift;
my $file1    = catfile($testDir, "out-ref", $testFile);
my $file2    = catfile($testDir, "out-dyn", $testFile);

if (-f $testDir && -f $testFile) {
	$file1 = $testDir;
	$file2 = $testFile;
}
elsif (!-f $file1 || !-f $file2) {
	die "Couldn't figure out what files to diff from the options\n";
}

open(I, "<$file1") || die "Couldn't open $file1: $!\n";
my $file1Contents = join('', <I>);
close(I);

open(I, "<$file2") || die "Couldn't open $file2: $!\n";
my $file2Contents = join('', <I>);
close(I);

$file1Contents =~ s|\r|\\r|g;
$file1Contents =~ s|\n|\\n\n|g;

$file2Contents =~ s|\r|\\r|g;
$file2Contents =~ s|\n|\\n\n|g;

my $diff = Text::Diff::diff(\$file1Contents, \$file2Contents, { STYLE => 'Unified' });
print $diff;

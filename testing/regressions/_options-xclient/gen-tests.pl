#!/usr/bin/perl

use strict;
use Getopt::Std;

my $comment    = "# Generated " . scalar(localtime) . " by $0 " . join(' ', map { "'$_'" } @ARGV);

my %opts = ();
getopts('d:n:o:v:i:p:s:r', \%opts) || die "Couldn't process opts\n";
# d - outdir
# n - startnum
# o - option name
# v - valid arg string
# i - invalid arg string
# p - empty arg will prompt.  Argument is the prompt string to expect
# s - swaks command.  Provide this on command line if different than the standard swaks encoded in this script
# r - force regenerate file even if file already exists

my $outdir     = $opts{'d'};
my $startnum   = $opts{'n'};
my $option     = $opts{'o'};
my $validArg   = $opts{'v'};
my $invalidArg = $opts{'i'};
my $prompt     = $opts{'p'};
my $swaks      = $opts{'s'};
my $forceRegen = $opts{'r'};
my $testNum;
my $testText;
my @standardLines = (
	$comment,
	'',
	'auto: REMOVE_FILE,CREATE_FILE,MUNGE,COMPARE_FILE %TESTID%.stdout %TESTID%.stderr',
	'',
);

if (!$outdir || !-d $outdir) {
	print STDERR "Invalid OUTDIR '$outdir'\n";
	exit;
}

if (!length($startnum) || $startnum !~ /^\d+$/) {
	print STDERR "Invalid STARTNUM '$startnum'\n";
	exit;
}

if (!$option) {
	print STDERR "Invalid OPTION '$option'\n";
	exit;
}

if (!$swaks) {
	$swaks = '%SWAKS% --dump XCLIENT --to user@example.com --from recip@example.com --helo hserver --server "ser.ver"';
}

printf "%05d --$option\n", $startnum;

#####################

$testNum  = $startnum + 0;
$testText = "$option, command line, no arg";
if ($prompt) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"auto: INTERACT '$swaks --$option' '$prompt' '$validArg'",
	]);
}
else {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --$option",
	]);
}

$testNum  = $startnum + 1;
$testText = "$option, command line, valid arg";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --$option $validArg"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 2;
$testText = "$option, command line, invalid arg";
if ($invalidArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --$option $invalidArg"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 3;
$testText = "$option, command line, no-option";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	'test action: CMD_CAPTURE ' . $swaks . " \\\n    --$option $validArg --no-$option"
]);

#####################

$testNum  = $startnum + 10;
$testText = "$option, config, no arg";
if ($prompt) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option'",
		"auto: INTERACT '$swaks --config %OUTDIR%/swaksrc-%TESTID%' '$prompt' '$validArg'",
	]);
}
else {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option'",
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
	]);
}

$testNum  = $startnum + 11;
$testText = "$option, config, valid arg";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option $validArg'",
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 12;
$testText = "$option, config, invalid arg";
if ($invalidArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option $invalidArg'",
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 13;
$testText = "$option, config, no-option";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option $validArg\\nno-$option'",
	'test action: CMD_CAPTURE ' . $swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
]);

#####################

my $varOption = $option;
$varOption =~ s/-/_/g;

$testNum  = $startnum + 20;
$testText = "$option, env var, no arg";
if ($prompt) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: SET_ENV SWAKS_OPT_$varOption",
		"auto: INTERACT '$swaks' '$prompt' '$validArg'",
	]);
}
else {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: SET_ENV SWAKS_OPT_$varOption",
		'test action: CMD_CAPTURE ' . $swaks
	]);
}

$testNum  = $startnum + 21;
$testText = "$option, env var, valid arg";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: SET_ENV SWAKS_OPT_$varOption $validArg",
		'test action: CMD_CAPTURE ' . $swaks
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 22;
$testText = "$option, env var, invalid arg";
if ($invalidArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: SET_ENV SWAKS_OPT_$varOption $invalidArg",
		'test action: CMD_CAPTURE ' . $swaks
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 23;
$testText = "$option, env var, no-option";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	"pre action: SET_ENV SWAKS_OPT_$varOption $validArg",
	'test action: CMD_CAPTURE ' . $swaks . " --no-$option"
]);

#########################

$testNum  = $startnum + 30;
$testText = "$option command line, no arg (-option)";
if ($prompt) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"auto: INTERACT '$swaks -$option' '$prompt' '$validArg'",
	]);
}
else {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    -$option"
	]);
}

$testNum  = $startnum + 31;
$testText = "$option, command line, valid arg (-option=)";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    -$option=$validArg"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 32;
$testText = "$option, command line, valid arg (--option=)";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		'test action: CMD_CAPTURE ' . $swaks . " \\\n    --$option=$validArg"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}



exit;

sub saveTest {
	my $num    = shift;
	my $text   = shift;
	my $lines  = shift;
	my $testID = sprintf("%05d", $num);

	if (!-f "$outdir/$testID.test" || $forceRegen) {
		if (ref($lines)) {
			print "  $num $text\n";

			open(O, ">$outdir/$testID.test") || die "Couldn't write to $outdir/$testID.test: $!\n";
			print O join("\n", @$lines) . "\n";
			close(O);
		}
		else {
			print "  # $num $text\n";
		}
	}
}

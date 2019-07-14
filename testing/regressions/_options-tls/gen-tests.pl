#!/usr/bin/perl

use strict;

my $comment    = "# Generated " . scalar(localtime) . " by $0 " . join(' ', map { "'$_'" } @ARGV);

my $outdir     = shift;
my $startnum   = shift;
my $option     = shift;
my $validArg   = shift;
my $invalidArg = shift;
my $forceRegen = shift;

if (!$outdir || !-d $outdir) {
	print STDERR "Usage: $0 OUTDIR STARTNUM OPTION VALID-ARG INVALID-ARG\n";
	print STDERR "Invalid OUTDIR '$outdir'\n";
	exit;
}

if (!length($startnum) || $startnum !~ /^\d+$/) {
	print STDERR "Usage: $0 OUTDIR STARTNUM OPTION VALID-ARG INVALID-ARG\n";
	print STDERR "Invalid STARTNUM '$startnum'\n";
	exit;
}

if (!$option) {
	print STDERR "Usage: $0 OUTDIR STARTNUM OPTION [VALID-ARG] [INVALID-ARG]\n";
	print STDERR "Invalid OPTION '$option'\n";
	exit;
}

my @standardLines = (
	$comment,
	'',
	'auto: REMOVE_FILE,CREATE_FILE,MUNGE,COMPARE_FILE %TESTID%.stdout %TESTID%.stderr',
	'',
);
# tests 0 -> 350
# my $swaks = 'test action: CMD_CAPTURE %SWAKS% --dump TLS --to user@example.com --from recip@example.com --server "ser ver"';

# tests 400->650
my $swaks = 'test action: CMD_CAPTURE %SWAKS% --dump TLS --to user@example.com --from recip@example.com --tls --server "ser ver"';

# test 700
# my $swaks = 'test action: CMD_CAPTURE %SWAKS% --dump TLS --to user@example.com --from recip@example.com --tls --tls-key %TESTDIR%/%TESTID%.test --server "ser ver"';

# test 750
# my $swaks = 'test action: CMD_CAPTURE %SWAKS% --dump TLS --to user@example.com --from recip@example.com --tls --tls-cert %TESTDIR%/%TESTID%.test --server "ser ver"';
my $testNum;
my $testText;

printf "%05d --$option\n", $startnum;

#####################

$testNum  = $startnum + 0;
$testText = "$option, command line, no arg";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	$swaks . " \\\n    --$option",
]);

$testNum  = $startnum + 1;
$testText = "$option, command line, valid arg";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		$swaks . " \\\n    --$option $validArg"
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
		$swaks . " \\\n    --$option $invalidArg"
	]);
}
else {
	saveTest($testNum, $testText, 0);
}

$testNum  = $startnum + 3;
$testText = "$option, command line, no-option";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	$swaks . " \\\n    --$option $validArg --no-$option"
]);

#####################

$testNum  = $startnum + 10;
$testText = "$option, config, no arg";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option'",
	$swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
]);


$testNum  = $startnum + 11;
$testText = "$option, config, valid arg";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: MERGE %OUTDIR%/swaksrc-%TESTID% string:'$option $validArg'",
		$swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
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
		$swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
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
	$swaks . " \\\n    --config %OUTDIR%/swaksrc-%TESTID%"
]);

#####################

my $varOption = $option;
$varOption =~ s/-/_/g;

$testNum  = $startnum + 20;
$testText = "$option, env var, no arg";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	"pre action: SET_ENV SWAKS_OPT_$varOption",
	$swaks
]);


$testNum  = $startnum + 21;
$testText = "$option, env var, valid arg";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		"pre action: SET_ENV SWAKS_OPT_$varOption $validArg",
		$swaks
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
		$swaks
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
	$swaks . " --no-$option"
]);

#########################

$testNum  = $startnum + 30;
$testText = "$option command line, no arg (-option)";
saveTest($testNum, $testText, [
	@standardLines, "title: $testText", '',
	$swaks . " \\\n    -$option"
]);

$testNum  = $startnum + 31;
$testText = "$option, command line, valid arg (-option=)";
if ($validArg) {
	saveTest($testNum, $testText, [
		@standardLines, "title: $testText", '',
		$swaks . " \\\n    -$option=$validArg"
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
		$swaks . " \\\n    --$option=$validArg"
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

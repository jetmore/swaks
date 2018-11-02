#!/usr/bin/perl

use Text::ParseWords;

my $testDir = shift || die "Please provide the path to the test directory\n";
my $outDir  = "$testDir/out";

my $tokens = {
	'global' => {
		'%SWAKS%' => 'swaks',
		'%TESTDIR%' => $testDir,
		'%OUTDIR%' => $outDir,
	},
	'local' => {},
};
if ($ENV{TEST_SWAKS}) {
	$tokens->{'global'}{'%SWAKS%'} = $ENV{TEST_SWAKS};
}

if (!-d $outDir) {
	mkdir($outDir) || die "Can't mkdir($outDir): $!\n";
	open(O, ">$outDir/.gitignore") || die "Can't open $outDir/.gitignore for writing: $!\n";
	print O "*\n";
	close(O);
}

opendir(D, $testDir) || die "Couldn't opendir($testDir): $!\n";
my(@testDefs) = grep(/^\d+\.test/, readdir(D));
closedir(D);

my $testIDs = {};
foreach my $testFile (sort @testDefs) {
	my $testObj = readTestFile("$testDir/$testFile");
	if ($testIDs->{$testObj->{id}}) {
		die "saw test id $testObj->{id} more than once\n";
	}
	$testIDs->{$testObj->{id}} = 1;

	runTest($testDir, $outDir, $testObj);
}

exit;

sub runTest {
	my $testDir   = shift;
	my $outDir    = shift;
	my $obj       = shift;
	my $allTokens = {};

	# set local tokens (currently only %TESTID% can be set)
	$tokens->{'local'} = { '%TESTID%' => $obj->{'id'} }; # reset the local tokens and set id to the test ID

	# merge tokens into a single hash.  process global before local so that local will win if there are duplicates
	foreach my $tokenType ('global', 'local') {
		foreach my $token (keys(%{$tokens->{$tokenType}})) {
			$allTokens->{$token} = $tokens->{$tokenType}{$token};
		}
	}

	if ($obj->{'pre action'}) {
		foreach my $action (@{$obj->{'pre action'}}) {
			runAction($allTokens, $action);
		}
	}
	if ($obj->{'test action'}) {
		foreach my $action (@{$obj->{'test action'}}) {
			runAction($allTokens, $action);
		}
	}

	# long term I'd like to be able to chain results together. For now, just handle one at a time
	if ($obj->{'test result'}) {
		foreach my $result (@{$obj->{'test result'}}) {
			my $failed = runResult($allTokens, $result);
			if ($failed) {
				print "$obj->{id}: FAIL ($failed)\n";
			}
			else {
				print "$obj->{id}: PASS\n";
			}
		}
	}
}

sub runResult {
	my $tokens = shift;
	my $test   = shift;

	my($verb, @args) = shellwords(replaceTokens($tokens, $test));

	if ($verb eq 'COMPARE_FILE') {
		open(P, "diff -u $args[0] $args[1] |") || die "Can't run diff: $!\n";
		my $diff = join('', <P>);
		close(P);

		if ($diff) {
			my $diffFile = $tokens->{'%OUTDIR%'} . '/' . $tokens->{'%TESTID%'} . '.diff';
			open(O, ">$diffFile") || die "Can't write to $diffFile: $!\n";
			print O $diff;
			close(O);
			return($diffFile);
		}
		else {
			return(0);
		}
	}
	else {
		die "Unknown result verb $verb\n";
	}
}

sub runAction {
	my $tokens = shift;
	my $action = shift;

	my($verb, @args) = shellwords(replaceTokens($tokens, $action));

	if ($verb eq 'REMOVE_FILE') {
		unlink(@args);
	}
	elsif ($verb eq 'CMD') {
		system(@args);
	}
	else {
		die "Unknown action verb $verb\n";
	}
}

sub replaceTokens {
	my $tokens = shift;
	my $action = shift;

	foreach my $token (keys %$tokens) {
		$action =~ s/$token/$tokens->{$token}/g
	}

	return($action);
}

sub readTestFile {
	my $file = shift;
	my $obj  = {};

	open(I, "<$file") || die "Couldn't open $file: $!\n";
	while (defined(my $line = <I>)) {
		chomp();
		if ($line =~ /^([^:]+):\s+(.*)$/) {
			my $testKey = $1;
			my $testArg = $2;
			if ($testKey eq 'id' || $testKey eq 'title') {
				$obj->{$testKey} = $testArg;
			}
			elsif ($testKey eq 'pre action' || $testKey eq 'test action' || $testKey eq 'test result') {
				push(@{$obj->{$testKey}}, $testArg);
			}
			else {
				die "Unknown test key in $file: $testKey\n";
			}
		}
		else {
			die "Unknown line format in $file: $line\n";
		}
	}
	if (!$obj->{id}) {
		die "Couldn't find test id in $file\n";
	}

	return($obj);
}

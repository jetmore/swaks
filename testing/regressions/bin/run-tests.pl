#!/usr/bin/env perl

# - example usage (run every test under _options-data):
#  - SWAKS_TEST_SWAKS=../../swaks bin/run-tests.pl _options-data
# - example usage (run every test under _options-data matching ^05)
#  - SWAKS_TEST_SWAKS=../../swaks bin/run-tests.pl _options-data ^05
# - example usage (run every test without prompting the user, but save the results):
#  - SWAKS_TEST_SWAKS=../../swaks bin/run-tests.pl --headless --outfile var/results.1570707905 _options-data
# - example usage (only run tests that failed during the previous headless run):
#  - SWAKS_TEST_SWAKS=../../swaks bin/run-tests.pl --errors --infile var/results.1570707905 _options-data

use strict;
use Capture::Tiny;
use Cwd qw(realpath);
use File::Copy qw();
use File::Spec::Functions qw(:ALL);
use FindBin qw($Bin);
use Getopt::Long;
use Proc::Background;
use Sys::Hostname;
use Term::ReadKey;
use Text::ParseWords;
use Text::Diff qw();

$| = 1;

# --headless - don't prompt the user, just run and display the results
# --outfile - save the results in a way that can be read by infile
# --infile - load state of a previous run.  Only really useful in conjunction with --errors
# --errors - load the state from --infile.  Only run tests that were marked as failures in the infile state.
# --skip-only - temporarily ignore the skip directive in a test and run it anyway. Ignore non-skip tests
my $opts = {};
GetOptions($opts, 'headless|h!', 'outfile|o=s', 'infile|i=s', 'errors|e!', 'skip-only') || die "Couldn't understand options\n";

my $testDir =  shift || die "Please provide the path to the test directory\n";
$testDir    =~ canonpath($testDir); # remove trailing slashes
my $testRe  =  shift || '.'; # pattern to match test IDs against. Allows to run subset of tests by specifying, eg, '005.'
my $outDir  =  catfile($testDir, "out-dyn");
my $refDir  =  catfile($testDir, "out-ref");
my $certDir =  catfile($Bin, '..', '..', 'certs');
my $autoCat =  $ENV{SWAKS_TEST_AUTOCAT} ? 1 : 0;

my @forks        = ();
my $customTokens = {};
my $tokens       = {
	'global' => {
		'%SWAKS%'    => $^O eq 'MSWin32' ? 'swaks.pl' : 'swaks',
		'%TESTDIR%'  => $testDir,
		'%OUTDIR%'   => $outDir,
		'%REFDIR%'   => $refDir,
		'%CERTDIR%'  => $certDir,
		'%HOSTNAME%' => get_hostname(),
		'%USERNAME%' => get_username(),
	},
	'local' => {},
};
if ($ENV{SWAKS_TEST_SWAKS}) {
	if ($ENV{SWAKS_TEST_SWAKS} =~ m|[/\\]|) {
		$ENV{SWAKS_TEST_SWAKS} = realpath(rel2abs($ENV{SWAKS_TEST_SWAKS}));
	}
	$tokens->{'global'}{'%SWAKS%'} = $ENV{SWAKS_TEST_SWAKS};
}
if ($ENV{SWAKS_TEST_SERVER}) {
	if ($ENV{SWAKS_TEST_SERVER} =~ m|[/\\]|) {
		$ENV{SWAKS_TEST_SERVER} = realpath(rel2abs($ENV{SWAKS_TEST_SERVER}));
	}
	$tokens->{'global'}{'%TEST_SERVER%'} = $ENV{SWAKS_TEST_SERVER};
}

if (!-d $testDir) {
	die "invalid test suite (not a directory): $testDir\n";
}
if (!-d $outDir) {
	mkdir($outDir) || die "Can't mkdir($outDir): $!\n";
	my $gitignore = catfile($outDir, ".gitignore");
	open(O, ">$gitignore") || die "Can't open $gitignore for writing: $!\n";
	print O "*\n";
	close(O);
}
if (!-d $refDir) {
	mkdir($refDir) || die "Can't mkdir($refDir): $!\n";
}

my @testDefs = ();
if ($opts->{errors}) {
	die "--infile is required when running with --errors\n" if (!$opts->{infile});
	open(I, "<$opts->{infile}") || die "Can't open infile $opts->{infile}: $!\n";
	while (my $line = <I>) {
		chomp();
		if ($line =~ m|^$testDir/(\d+): FAIL|) {
			push(@testDefs, "$1.test");
		}
	}
	close(I);
}
else {
	opendir(D, $testDir) || die "Couldn't opendir($testDir): $!\n";
	(@testDefs) = grep(/^\d+\.test/, readdir(D));
	closedir(D);
}

TEST_EXECUTION:
foreach my $testFile (sort @testDefs) {
	restoreEnv();

	my $testObj = readTestFile(catfile($testDir, $testFile));
	next if ($testObj->{id} !~ /$testRe/);

	my $result = runTest($testDir, $outDir, $testObj);
}

exit;

sub restoreEnv {
	foreach my $key (keys %G::restoreEnv) {
		if (defined($G::restoreEnv{$key})) {
			# print STDERR "RES_ENV $key: value defined, setting ENV{$key} to $G::restoreEnv{$key}\n";
			$ENV{$key} = $G::restoreEnv{$key};
		}
		else {
			# print STDERR "RES_ENV $key: value !defined, deleting ENV{$key}\n";
			delete($ENV{$key});
		}
	}
	$G::restoreEnv = ();
	$G::debug = {};
}

sub runTest {
	my $testDir   = shift;
	my $outDir    = shift;
	my $obj       = shift;
	my $allTokens = {};
	@forks        = ();

	# set local tokens (currently only %TESTID% can be set)
	$tokens->{'local'} = { '%TESTID%' => $obj->{'id'} }; # reset the local tokens and set id to the test ID

	# merge tokens into a single hash.  process global before local so that local will win if there are duplicates
	foreach my $tokenType ('global', 'local') {
		foreach my $token (keys(%{$tokens->{$tokenType}})) {
			$allTokens->{$token} = $tokens->{$tokenType}{$token};
		}
	}

	if ($opts->{'skip-only'} && !$obj->{'skip'}) {
		return;
	}
	elsif (!$opts->{'skip-only'} && $obj->{'skip'}) {
		saveResult("$testDir/$obj->{id}: SKIP: $obj->{'skip'}");
		return;
	}

	if ($obj->{'once action'}) {
		# 'once action's are tracked across the entire test run and only need to be run exactly once for the entire run
		foreach my $action (@{$obj->{'once action'}}) {
			if (!$G::onceActions{$action}) {
				# print STDERR "runAction($action)\n";
				runAction($allTokens, $action);
				$G::onceActions{$action} = 1;
			}
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

	if ($obj->{'test result'}) {
		my $failed = runResult($obj, $allTokens, $obj->{'test result'});
		my $result = "$testDir/$obj->{id}: " . ($failed ? "FAIL ($failed)" : 'PASS');
		saveResult($result);
	}

	foreach my $proc (@forks) {
		$proc->die();
	}
}

sub saveExit {
	my $id   = shift;
	my $exit = shift;
	my $file = catfile($outDir, $id . '.exits');

	open(O, ">>$file") || die "Couldn't open $file to write: $!\n";
	printf O "%-15s %3d   %s\n", $exit->[0], $exit->[1], join(' ', @{$exit->[2]});
	close(O);
}

sub saveResult {
	my $string = shift;

	print $string, "\n";

	if ($opts->{outfile}) {
		open(O, ">>$opts->{outfile}") || die "Can't open $opts->{outfile} to write: $!\n"; # cache this in future
		print O $string, "\n";
		close(O);
	}
}

sub genDiffs {
	my $baseDiffFile = shift;
	my $refFile      = shift;
	my $dynFile      = shift;
	my $leDiffFile   = $baseDiffFile . '.showle';
	my $noleDiffFile = $baseDiffFile . '.nole';

	unlink($baseDiffFile, $leDiffFile, $noleDiffFile);

	my $diff = Text::Diff::diff($refFile, $dynFile, { STYLE => 'Unified' });

	if (!$diff) {
		return;
	}

	open(O, ">$baseDiffFile") || die "Can't write to $baseDiffFile: $!\n";
	print O $diff;
	close(O);

	$diff =~ s|\r|\\r|g;
	$diff =~ s|\n|\\n\n|g;
	open(O, ">$leDiffFile") || die "Can't write to $leDiffFile: $!\n";
	print O $diff;
	close(O);

	open(I, "<$refFile");
	my $refData = join('', <I>);
	close(I);
	open(I, "<$dynFile");
	my $dynData = join('', <I>);
	close(I);

	$refData =~ s|\r||g;
	$dynData =~ s|\r||g;

	open(O, ">$noleDiffFile") || die "Can't write to $noleDiffFile: $!\n";
	print O Text::Diff::diff(\$refData, \$dynData, { STYLE => 'Unified' });
	close(O);
}


sub runResult {
	my $testObj = shift;
	my $tokens  = shift;
	my $tests   = shift;
	my $pass    = 1;
	my @return  = ();

	FILE:
	foreach my $test (@$tests) {
		debug('result', $test);

		my($verb, @args) = mshellwords(replaceTokens($tokens, $test));

		if ($verb eq 'COMPARE_FILE') {
			debug('COMPARE_FILE', join('; ', @args));
			if (-f $args[0] && -f $args[1]) {
				my $diffFile     = catfile($tokens->{'%OUTDIR%'}, (splitpath($args[0]))[2] . '.diff');
				unlink($diffFile);
				genDiffs($diffFile, $args[0], $args[1]);

				if (-e $diffFile) {
					if (!$opts->{'headless'}) {
						my $autoCatRan = 0;
						my $action     = $testObj->{'test action'}[0];
						INTERACT:
						while (1) {
							print "Test ", catfile($tokens->{'%TESTDIR%'}, $tokens->{'%TESTID%'}), " is about to fail.\n",
							      "DIFF:   $args[0], $args[1]\n",
							      ($testObj->{title} ? "TITLE:  $testObj->{title}\n" : ''),
							      "ACTION: $action\n",
							      "(i)gnore file; review (d)iff ((w)ith or with(o)ut line endings); (e)dit, (r)erun, or (s)kip test; (u)nmunge; (a)ccept new results; (q)uit: ";

							my $input;
							if (!$autoCat || $autoCatRan) {
								# read a single character w/o requiring user to hit enter
								ReadMode 'cbreak';
								$input = ReadKey(0);
								ReadMode 'normal';
								print "$input\n";
							}
							elsif ($autoCat) {
								$input = 'd';
								print "autoCat\n";
							}

							if ($input eq 'i') {
								# ignore is to ignore this specific file failure
								last INTERACT;
							}
							elsif ($input eq 'd' || $input eq 'w' || $input eq 'o') {
								my $showFile = $diffFile;
								$showFile = "$diffFile.showle" if ($input eq 'w');
								$showFile = "$diffFile.nole" if ($input eq 'o');

								my @cmds = ('intcat');
								if ($input eq 'd' && $autoCat && !$autoCatRan) {
									$autoCatRan = 1;
								}
								else {
									if (length($ENV{'PAGER'})) {
										unshift(@cmds, $ENV{'PAGER'});
									}
									if (length($ENV{'SWAKS_TEST_PAGER'})) {
										unshift(@cmds, $ENV{'SWAKS_TEST_PAGER'});
									}
									if (scalar(@cmds) == 1) {
										print "WARNING: consider setting SWAKS_TEST_PAGER or PAGER environment variables\n";
									}
								}

								CMD:
								foreach my $cmd (@cmds) {
									if ($cmd eq 'intcat') {
										open(I, $showFile) || print "ERROR: unable to open $showFile: $!\n";
										while (<I>) {
											print;
										}
										close(I);
									}
									else {
										debug('exec', "$cmd $showFile");
										if (system($cmd, $showFile) == -1) {
											print "ERROR: unable to execute '$cmd $showFile': $!\n";
											next CMD;
										}
										last CMD;
									}
								}
								next INTERACT;
							}
							elsif ($input eq 'e') {
								my $editor = $ENV{'SWAKS_TEST_EDITOR'} || $ENV{'VISUAL'} || $ENV{'EDITOR'};
								my $file   = catfile($tokens->{'%TESTDIR%'}, "$tokens->{'%TESTID%'}.test");
								if (!-e $editor) {
									print STDERR "No valid editor found, consider setting SWAKS_TEST_EDITOR, VISUAL, or EDITOR environment variables\n";
									next INTERACT;
								}
								debug('exec', "$editor $file");
								system($editor, $file);
								redo TEST_EXECUTION;
							}
							elsif ($input eq 'u') {
								$action = join(' ', mshellwords(replaceTokens($tokens, $testObj->{'test action'}[0])));
								next INTERACT;
							}
							elsif ($input eq 'r') {
								redo TEST_EXECUTION;
							}
							elsif ($input eq 's') {
								# skip is like ignore, but for the entire test, not just for this file
								push(@return, $diffFile, 'SKIPPED');
								last FILE;
							}
							elsif ($input eq 'a') {
								File::Copy::copy($args[1], $args[0]);
								redo TEST_EXECUTION;
							}
							elsif ($input eq 'q') {
								exit;
							}
							else {
								print "ERROR: unknown option '$input'\n";
							}
						}
					}

					push(@return, $diffFile);
				}
				else {
					push(@return, '');
				}
			}
			else {
				push(@return, "Can't COMPARE_FILE($args[0], $args[1]), one or both files don't exist");
			}
		}
		elsif (!$verb) {
			die "Unable to parse result string `$test`\n";
		}
		else {
			die "Unknown result verb $verb (args = ", join(',', @args), ")\n";
		}
	}

	if (grep(/./, @return)) {
		return join('; ', @return);
	}
	else {
		return '';
	}
}

sub runAction {
	my $tokens = shift;
	my $action = shift;

	debug('action', $action);

	my($verb, @args) = mshellwords(replaceTokens($tokens, $action));

	# print "\$verb = $verb\n";
	# for (my $i = 0; $i < scalar(@args); $i++) {
	# 	print "ARG $i) $args[$i]\n";
	# }

	if ($verb eq 'REMOVE_FILE') {
		debug('REMOVE_FILE', join('; ', @args));
		unlink(@args);
	}
	elsif ($verb eq 'CMD') {
		$args[0] =~ s|/|\\|g if ($^O eq 'MSWin32');
		debug('CMD', join('; ', @args));
		debug('exec', join(' ', map { "'$_'" } @args));
		my $exit = system(@args);
		saveExit($tokens->{'local'}{'%TESTID%'}, [ $verb, $exit >> 8, \@args ]);
	}
	elsif ($verb =~ /^CMD_CAPTURE(?::(\S+))?$/) {
		my $suffix     = $1 ? ".$1" : '';
		$args[0]       =~ s|/|\\|g if ($^O eq 'MSWin32');
		debug('CMD_CAPTURE', join('; ', @args));
		my $stdoutFile = catfile($tokens->{'%OUTDIR%'}, $tokens->{'%TESTID%'} . '.stdout' . $suffix);
		my $stderrFile = catfile($tokens->{'%OUTDIR%'}, $tokens->{'%TESTID%'} . '.stderr' . $suffix);
		my $stdinFile  = (grep(/^STDIN:/, @args))[0];
		@args          = grep(!/^STDIN:/, @args);

		$stdinFile =~ s/^STDIN://;
		my $exit = captureOutput(\@args, $stdoutFile, $stderrFile, $stdinFile);
		saveExit($tokens->{'%TESTID%'}, [ $verb, $exit, \@args ]);
	}
	elsif ($verb eq 'FORK') {
		$args[0] =~ s|/|\\|g if ($^O eq 'MSWin32');
		debug('FORK', join('; ', @args));
		debug('exec', join(' ', map { "'$_'" } @args));
		my $proc = Proc::Background->new(@args);
		if (!$proc->alive()) {
			die "Unable to FORK @args: $!($@)\n";
		}
		push(@forks, $proc);
	}
	elsif ($verb eq 'DEFINE') {
		debug('DEFINE', join('; ', @args));
		$customTokens->{$args[0]} = $args[1];
	}
	elsif ($verb eq 'CREATE_FILE') {
		debug('CREATE_FILE', join('; ', @args));
		if (!-e $args[0]) {
			open(O, ">$args[0]") || die "Couldn't open file $args[0] to write: $!\n";
			close(O);
		}
	}
	elsif ($verb eq 'SET_ENV') {
		debug('SET_ENV', join('; ', @args));
		if (!exists($ENV{$args[0]})) {
			# print STDERR "SET_ENV $args[0] - !exists, marking as undef in the restore hash\n";
			$G::restoreEnv{$args[0]} = undef();
		}
		else {
			# print STDERR "SET_ENV $args[0] - exists, marking as $ENV{$args[0]} in the restore hash\n";
			$G::restoreEnv{$args[0]} = $ENV{$args[0]};
		}

		if ($args[1] eq '--UNSET--') {
			# print STDERR "SET_ENV $args[0] - value is --UNSET--, deleting ENV{$args[0]}\n";
			delete($ENV{$args[0]});
		}
		else {
			my $tv = ($^O eq 'MSWin32' && !$args[1]) ? '<>' : $args[1];
			# print STDERR "SET_ENV $args[0] - setting ENV{$args[0]} to $tv\n";
			$ENV{$args[0]} = $tv;
		}
	}
	elsif ($verb eq 'MERGE') {
		debug('MERGE', join('; ', @args));
		my $outFile = shift(@args);
		my %post    = ();
		open(O, ">$outFile") || die "MERGE: Can't open $outFile to write: $!\n";
		#print "opened $outFile\n";
		foreach my $part (@args) {
			if ($part =~ /^file:(.*)$/) {
				my $file = $1;
				open(I, "<$file") || die "MERGE: Can't read from $file: $!\n";
				print O join('', <I>);
				close(I);
			}
			elsif ($part =~ /^string:(.*)$/) {
				my $string = $1;
				$string =~ s/\\n/\n/g;
				#print "adding string $string to $outFile\n";
				print O $string;
			}
			elsif ($part =~ /^(mode|owner|group):(.*)$/) {
				$post{$1} = $2;
			}
			else {
				die "MERGE: unknown part format $part\n";
			}
		}
		close(O);

		if ($^O ne 'MSWin32') {
			if (length($post{mode})) {
				chmod(oct($post{mode}), $outFile);
			}
			elsif (length($post{owner})) {
				chown($post{owner}, -1, $outFile);
			}
			elsif (length($post{group})) {
				chown(-1, $post{group}, $outFile);
			}
		}
	}
	elsif ($verb eq 'MUNGE') {
		debug('MUNGE', join('; ', @args));
		if ($args[0] =~ /^file:(.*)$/) {
			my $file  = $1;
			shift(@args);

			my @lines = ();
			open(I, "<$file") || die "Can't open munge file $file: $!\n";
			@lines = <I>;
			close(I);

			foreach my $munge (@args) {
				my($function,@fArgs) = split(',', $munge);
				unshift(@fArgs, '\@lines');
				my $functionCall = "$function(" . join(', ', @fArgs) . ");";
				eval $functionCall;
				if ($@) {
					die "Couldn't run $munge: $@\n";
				}
			}
			munge_general(\@lines, '.?', quotemeta($tokens->{'%SWAKS%'}), '%SWAKS_COMMAND%');
			munge_general(\@lines, '.?', quotemeta($tokens->{'%TEST_SERVER%'}), '%TEST_SERVER%');

			open(O, ">$file") || die "Couldn't write to $file: $!\n";
			print O join('', @lines);
			close(O);
		}
		else {
			die "MUNGE verb seen but no associated file\n";
		}
	}
	elsif (!$verb) {
		die "Unable to parse action string `$action`\n";
	}
	else {
		die "Unknown action verb $verb (args = ", join(',', @args), ")\n";
	}
}

sub replaceTokens {
	my $tokens = shift;
	my $action = shift;

	foreach my $source ($tokens, $customTokens) {
		foreach my $token (keys %$source) {
			$action =~ s/$token/$source->{$token}/g;
			debug('token', "REPLACE $token -> $source->{$token}, $action\n");
		}
	}

	return($action);
}

sub readTestFile {
	my $file     = shift;
	my $obj      = {};
	my $fullLine = '';

	open(I, "<$file") || die "Couldn't open $file: $!\n";
	LINE:
	while (defined(my $line = <I>)) {
		chomp($line);

		# handle continuations
		if ($line =~ s/\\$//) {
			$fullLine .= $line;
			next LINE;
		}
		else {
			$fullLine .= $line;
		}

		# handle specific platforms
		if ($fullLine =~ s/IFOS(!)?=(\S+) //) {
			my $negate = $1;
			my $testOs = $2;
			my $realOs = $^O;

			# pre action: IFOS=MSWin32 SET_ENV LC_ALL Czech
			# pre action: IFOS!=MSWin32 SET_ENV LC_ALL cs_CZ.UTF-8
			# Windows:  IFOS=MSWin32 = (1 && 0) || (0 && 1), IFOS!=MSWin32 = (1 && 1) || (0 && 0)
			# Linux:    IFOS=MSWin32 = (0 && 0) || (1 && 1), IFOS!=MSWin32 = (0 && 1) || (1 && 0)
			if (($testOs eq $realOs && $negate) || ($testOs ne $realOs && !$negate)) {
				$fullLine = '';
				next LINE;
			}
		}


		if ($fullLine =~ /^(\w[^:]+):\s+(.*)$/) {
			my $testKey = $1;
			my $testArg = $2;
			if ($testKey eq 'title' || $testKey eq 'skip') {
				$obj->{$testKey} = $testArg;
			}
			elsif ($testKey eq 'debug') {
				$obj->{$testKey} = { map { $_ => 1 } (split(/,\s*/, $testArg)) };
				$G::debug        = $obj->{$testKey};
			}
			elsif ($testKey =~ /^(pre action|test action|test result|once action|auto)$/) {
				push(@{$obj->{$testKey}}, $testArg);
			}
			else {
				die "Unknown test key in $file: $testKey\n";
			}
		}
		elsif ($fullLine !~ /^\s*$/ && $fullLine !~ /^\s*#/) {
			die "Unknown line format in $file: $fullLine\n";
		}

		$fullLine = '';
	}
	my $idFile = (splitpath($file))[2];
	if ($idFile =~ m%^(.+)\.[^.]+$%) {
		$obj->{id} = $1;
	}
	else {
		die "Couldn't generate test id from filename $file\n";
	}

	# we add these onto the end of the ones that are statically specified.  For the most part it won't matter, but in particular we want
	# our COMPARE_FILE 'test action's to happen AFTER the actual test action CMD(_CAPTURE)?
	if (exists($obj->{'auto'}) && ref($obj->{'auto'}) eq 'ARRAY') {
		foreach my $auto (@{$obj->{'auto'}}) {
			# my($types, @files) = split(' ', $auto);
			my($types, @files) = mshellwords($auto);
			foreach my $type (split(/,/, $types)) {
				if ($type eq 'REMOVE_FILE') {
					map { push(@{$obj->{'pre action'}}, "REMOVE_FILE " . catfile('%OUTDIR%', $_)); } (@files);
				}
				elsif ($type eq 'CREATE_FILE') {
					map { push(@{$obj->{'pre action'}}, "CREATE_FILE %REFDIR%/$_"); } (@files);
				}
				elsif ($type eq 'MUNGE') {
					map { push(@{$obj->{'test action'}}, "MUNGE file:" . catfile('%OUTDIR%', $_) . " munge_standard"); } (@files);
				}
				elsif ($type eq 'COMPARE_FILE') {
					# if we're comparing stdout and stderr, manipulate the list to compare stderr first.  It turns
					# out that seeing errors first is much more useful, but I don't want to modify all the existing tests
					my @filesSorted = grep(/\.stderr/, @files);
					push(@filesSorted, grep(/\.stdout/, @files), grep(!/\.(stdout|stderr)/, @files));
					map { push(@{$obj->{'test result'}}, "COMPARE_FILE " . catfile('%REFDIR%', $_) .' ' . catfile('%OUTDIR%', $_)); } (@filesSorted);
				}
				elsif ($type eq 'INTERACT') {
					# my $infile = catfile('%OUTDIR%', '%TESTID%.stdin');
					# push(@{$obj->{'pre action'}}, "REMOVE_FILE $infile");
					my $stdin = "STDIN:LITERAL:";
					my $cmd   = shift(@files);
					while (scalar(@files)) {
						my $expect   = shift(@files);
						my $response = shift(@files);
						$stdin .= "$response\\n";
					}
					unshift(@{$obj->{'test action'}}, "CMD_CAPTURE $cmd '$stdin'");


					# if ($^O eq 'MSWin32') {
					# 	$obj->{'skip'} ||= "INTERACTive testing not currently supported on windows";
					# }
					# my $file     = catfile('%OUTDIR%', '%TESTID%.expect');
					# push(@{$obj->{'pre action'}}, "REMOVE_FILE $file");

					# my $cmd       = shift(@files);
					# my $expectStr = "MERGE $file string:'spawn $cmd\\n' ";
					# while (scalar(@files)) {
					# 	my $expect   = shift(@files);
					# 	my $response = shift(@files);
					# 	$expectStr  .= "string:'expect \"$expect\"\\n' string:'send -- \"$response\\r\"\\n' ";
					# }
					# $expectStr .= "string:'interact\\n'";

					# push(@{$obj->{'pre action'}}, $expectStr);
					# unshift(@{$obj->{'test action'}}, "CMD_CAPTURE expect $file");
				}
				else {
					die "unknown 'auto' type $type\n";
				}
			}
		}
	}

	return($obj);
}

sub cmdquote {
	# start at 1 - never quote the actual command
	for (my $i = 1; $i < scalar(@_); $i++) {
		next if ($_[$i] !~ / /);
		# $_[$i] =~ s%%'\\''%g;
		$_[$i] =  '"' . $_[$i] .'"';
	}
	return join(' ', @_);
}

sub captureOutput {
	my $args    = shift;
	my $outFile = shift;
	my $errFile = shift;
	my $inFile  = shift;
	my $exit;
	my $debug   = join(' ', map { "'$_'" } (@$args)) . " >$outFile 2>$errFile";
	$debug     .= " <$inFile" if ($inFile);

	debug('exec', $debug);

	my $stdin = '';
	if ($inFile) {
		if ($inFile =~ s/^LITERAL://) {
			$stdin = $inFile;
			$stdin =~ s/\\n/\n/g;
		}
		else {
			open(I, "<$inFile") || die "Can't open inFile $inFile for reading: $!\n";
			$stdin = join('', <I>);
			close(I);
		}
	}

	my($stdout, $stderr, @rest) = Capture::Tiny::capture {
		if ($inFile) {
			my $command = cmdquote(@$args);
			open(P, "|-", join(' ', $command)) || die "Couldn't open pipe to $command: $!\n";
			print P $stdin;
			if (close(P)) {
				$exit = 0;
			}
			else {
				$exit = $?;
			}
		}
		else {
			$exit = system(@$args) >> 8;
		}
	};

	open(FILESTDOUT, ">$outFile") || die "Can't open new stdout file $outFile to write: $!\n";
	print FILESTDOUT $stdout;
	close(FILESTDOUT);

	open(FILESTDERR, ">$errFile") || die "Can't open new stderr file $errFile to write: $!\n";
	print FILESTDERR $stderr;
	close(FILESTDERR);

	return($exit);
}

sub get_hostname {
	return($G::hostname) if ($G::hostname);

	my $h = hostname();
	return("") if (!$h);

	my $l = (gethostbyname($h))[0];
	$G::hostname = $l || $h;

	return($G::hostname);
}

sub get_username {
	if ($^O eq 'MSWin32') {
		require Win32;
		return Win32::LoginName();
	}
	return $ENV{LOGNAME} || (getpwuid($<))[0];
}

sub debug {
	my $type   = shift;
	my $string = shift;

# use Data::Dumper;
# print Dumper($G::debug);
# exit;

# print "here $type $string\n";
	if ($G::debug->{$type} || $G::debug->{'ALL'}) {
		print STDERR "DEBUG $type $string\n";
	}
}

# yuck.  Just yuck
sub mshellwords {
	my $line = shift;
	my @return = ();

	if ($^O eq 'MSWin32') {
		$line =~ s/\\/::BACKSLASH::/g;
		foreach my $part (shellwords($line)) {
			$part =~ s/::BACKSLASH::/\\/g;
			push(@return, $part);
		}
	}
	else {
		@return = shellwords($line);
	}

	map { s/\%QUOTE_DOUBLE\%/"/g; s/\%QUOTE_SINGLE\%/'/g; } (@return);

	return @return;
}

sub munge_general {
	my $lines    = shift;
	my $consider = shift;
	my $find     = shift;
	my $replace  = shift;

	foreach my $line (@$lines) {
		if ($line =~ /$consider/) {
			$line =~ s/$find/$replace/g;
		}
	}
}

sub munge_globs {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_general($lines, $consider, 'GLOB\(0x[^\)]+\)', 'GLOB(0xdeadbeef)');
}

sub munge_mime_boundaries {
	my $lines    = shift;
	my $consider = shift || '.?';

	# munge_general($lines, $consider, '', 'MIME_BOUNDARY_${1}_99999');
	foreach my $line (@$lines) {
		if ($line =~ /$consider/) {
			$line =~ s/MIME_BOUNDARY_(\d\d\d)_\d+/MIME_BOUNDARY_${1}_99999/g;
		}
	}
}

sub munge_version {
	my $lines    = shift;
	my $consider = shift || '.?';

	foreach my $line (@$lines) {
		if ($line =~ /$consider/) {
			$line =~ s/\bv(\d\d\d\d\d\d\d\d\.\d|DEVRELEASE)\b/v99999999.9/g;
		}
	}
}

sub munge_dates {
	my $lines    = shift;
	my $consider = shift || '.?';

	my $find = '(Sun|Mon|Tue|Wed|Thu|Fri|Sat), '
	         . '\d\d '
	         . '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
	         . '\d\d\d\d '
	         . '\d\d:\d\d:\d\d '
	         . '[+-]\d\d\d\d';

	munge_general($lines, $consider, $find, 'Wed, 03 Nov 1999 11:24:29 -0500');
}

sub munge_message_ids {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_general($lines, $consider, '<\S+@\S+>', '<19991103112429.047942@localhost>');
}

sub munge_paths {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_general($lines, $consider, quotemeta($tokens->{'global'}{'%OUTDIR%'}), '%OUTDIR%');
	munge_general($lines, $consider, quotemeta($tokens->{'global'}{'%REFDIR%'}), '%REFDIR%');
	munge_general($lines, $consider, quotemeta($tokens->{'global'}{'%TESTDIR%'}), '%TESTDIR%');
	munge_general($lines, $consider, quotemeta($tokens->{'global'}{'%CERTDIR%'}), '%CERTDIR%');
}

sub munge_local_hostname {
	my $lines    = shift;
	my $consider = shift || '.?';

	return if (!$tokens->{'global'}{'%HOSTNAME%'});
	munge_general($lines, $consider, $tokens->{'global'}{'%HOSTNAME%'}, 'LOCAL_HOST_NAME');
}

sub munge_local_username {
	my $lines    = shift;
	my $consider = shift || '.?';

	return if (!$tokens->{'global'}{'%USERNAME%'});
	munge_general($lines, $consider, $tokens->{'global'}{'%USERNAME%'} . '@', 'LOCAL_USER_NAME@');
}

sub munge_copyright {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_general($lines, $consider, 'Copyright \(c\) 2003-2008,2010-\d\d\d\d John Jetmore <jj33\@pobox\.com>',
		'Copyright (c) 2003-2008,2010-YEAR John Jetmore <jj33@pobox.com>');
}

sub munge_tls_available_protocols {
	my $lines = shift;
	my $consider = shift || '.?';

	# make sure we have at least one TLSv1 family protocol, and if we do, replace with a generic string.
	# if we don't replace it, it won't match and will cause investigation, which is good since why aren't there any
	# tls protocols?
	munge_general($lines, $consider, 'available protocols = .*TLSv1.*', 'available protocols = TLS_PROTOCOL_LIST');
}

sub munge_open2_failure {
	my $lines = shift;

	# macOS and Debian's open2 have different error formats, munge them to be the same
	# macOS: open2: exec of /foo/bar failed at %SWAKS_COMMAND% line 165.
	# Debian: open2: exec of /foo/bar failed: No such file or directory at %SWAKS_COMMAND% line 165.
	munge_general($lines, 'open2: exec of', 'failed: No such file or directory at', 'failed at');
	munge_general($lines, 'open2: exec of', 'line \d+', 'line ###');
}

sub munge_tls_cipher {
	my $lines = shift;

	munge_general($lines, 'TLS started with cipher', 'TLS started with cipher .*', 'TLS started with cipher VERSION:CIPHER:BITS');
}

sub munge_time_lapse {
	my $lines = shift;

	munge_general($lines, '^=== response in', '^=== response in \d+\.\d+s', '=== response in FLOATs');
	munge_general($lines, '^=== response in', '^=== response in \d+s', '=== response in INTs');
}

# this is just a convenience so I can add new munges without having to manually apply them to all test files
sub munge_standard {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_globs($lines);
	munge_dates($lines, '(Subject|Date):');
	munge_message_ids($lines, 'Message-Id:');
	munge_version($lines, 'X-Mailer');
	munge_mime_boundaries($lines);
	munge_paths($lines);
	munge_local_hostname($lines);
	munge_local_username($lines);
	munge_copyright($lines);
	munge_tls_available_protocols($lines);
	munge_open2_failure($lines);
	munge_tls_cipher($lines);
	munge_time_lapse($lines);
}

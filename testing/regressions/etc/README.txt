
run-tests.pl - run a suite of tests
run-all.pl   - run all tests from all suites (or, with --errors, only errors from previous run)
check-env.pl - make sure the environment is suitable for executing the tests (see environment/tooling below for requirements)
runenv       - convenience script which sets TEST_SWAKS and PERL5LIB before executing the actual test script.  The version
               checked in to version control has the most-common values.  It can be edited locally to test different values, but
               different values should not be committed.
runenv.bat   - same as runenv, but specific to Windows.

--



environment/tooling:
	PAGER environment variable should be set to make displaying of diffs most useful (can just set it to 'less')
		- except on Windows, see below
	swaks must be in your path.  If TEST_SWAKS environment variable is set, it will be used instead of looking in PATH
		- on Windows, swaks _must_ be named swaks.pl
	perl must be in your path.
	the Capture::Tiny perl module needs to be installed
	the Text::Diff perl module needs to be installed
	all "optional" perl modules must be installed to run the test suite. (see Authen::NTLM note below)

--

Authen::NTLM

I'm not even sure this module is distributed anymore.  There are no tests for it, but I wanted to make a mandate that all modules need to be installed.
If you do not actually have Authen::NTLM installed, you can fake it for the purposes of testing by making sure that lib/authen-ntlm-local is in your
PERL5LIB:

export PERL5LIB=lib/authen-ntlm-local

This will load a fake version of the module that will make swaks happy for the purposes of testing

--

Windows

PAGER can be set if there's a useable pager, but because it's not obvious which pager to use (more and type are both CMD.exe builtins),
check-env.pl won't complain if it's not set on Windows

Swaks must end in .pl

I ran the following getting my test environment set up.  It's unclear if it's actually needed
	assoc .pl=PerlScript
	ftype PerlScript=C:\Strawberry\perl\bin\perl.exe "%1" %*
	setx PATHEXT %PATHEXT%;.pl

--

examples:

# make sure the local environment is suitable for running the test script
TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/check-env.pl



# run entire _options-auth suite
TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-tests.pl _options-auth

# run just one test from _options-auth suite
TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-tests.pl _options-auth 00300



# run every test unattended, leaving a record of results
TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-all.pl

# run only failed tests from the previous run-all.pl run
TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-all.pl --errors

# do another headless run - run headless and record results again, but only run tests that failed in previous tests (like --errors in headless mode)
TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-all.pl --winnow

# all the same examples as above, but using runenv to set the environment:

bin/runenv bin/check-env.pl
bin/runenv bin/run-tests.pl _options-auth
bin/runenv bin/run-tests.pl _options-auth 00300
bin/runenv bin/run-all.pl
bin/runenv bin/run-all.pl --errors
bin/runenv bin/run-all.pl --winnow

# all the same examples, but on windows:
bin\runenv bin\check-env.pl
bin\runenv bin\run-tests.pl _options-auth
bin\runenv bin\run-tests.pl _options-auth 00300
bin\runenv bin\run-all.pl
bin\runenv bin\run-all.pl --errors
bin\runenv bin\run-all.pl --winnow

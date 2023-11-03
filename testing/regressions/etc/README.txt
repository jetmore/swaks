
run-tests.pl - run a suite of tests
run-all.pl   - run all tests from all suites (or, with --errors, only errors from previous run)
check-env.pl - make sure the environment is suitable for executing the tests (see environment/tooling below for requirements)
runenv       - convenience script which sets SWAKS_TEST_SWAKS and other environment variables before executing the actual test
               script.  The version checked in to version control has the most-common values.  It can be edited locally to test
               different values, but different values should not be committed.
runenv.bat   - same as runenv, but specific to Windows.

--



environment/tooling:
	swaks MUST be in your path.
		- SWAKS_TEST_SWAKS environment variable can be set to an explicit swaks to avoid looking up in PATH
		- on Windows, swaks MUST be named swaks.pl
	perl MUST be in your path.
	Capture::Tiny perl module MUST be installed
	Text::Diff perl module needs MUST installed
	Proc::Background perl module MUST be installed
	Term::ReadKey perl module must be installed
	all "optional" perl modules MUST be installed to run the test suite (that is, `swaks --support` must show every option supported)
	SWAKS_TEST_SERVER environment variable MUST be set to a suitable path to run transaction tests.  The runenv default should be suitable everywhere
	SWAKS_TEST_PAGER environment variable SHOULD be set to make displaying of diffs most useful (can just set it to 'less')
		- except on Windows, see below
		- if SWAKS_TEST_PAGER is not set, PAGER will also be checked
	SWAKS_TEST_AUTOCAT environment variable MAY be set to 1 to force run-tests.pl to display a diff automatically on test failure
	SWAKS_TEST_EDITOR environment variable MAY be set to a text editor.  When (e)dit is chosen, the test scriopt will be opened using this variable
		- If SWAKS_TEST_EDITOR is not set, VISUAL and then EDITOR will also be checked

--

Windows

SWAKS_TEST_PAGER can be set if there's a useable pager, but because it's not obvious which pager to use (more and type are both CMD.exe builtins),
check-env.pl won't complain if it's not set on Windows

Swaks must end in .pl

I ran the following getting my test environment set up.  It's unclear if it's actually needed
	assoc .pl=PerlScript
	ftype PerlScript=C:\Strawberry\perl\bin\perl.exe "%1" %*
	setx PATHEXT %PATHEXT%;.pl

--

examples:

# make sure the local environment is suitable for running the test script
SWAKS_TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/check-env.pl



# run entire _options-auth suite
SWAKS_TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-tests.pl _options-auth

# run just one test from _options-auth suite
SWAKS_TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-tests.pl _options-auth 00300



# run every test unattended, leaving a record of results
SWAKS_TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-all.pl

# run only failed tests from the previous run-all.pl run
SWAKS_TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-all.pl --errors

# do another headless run - run headless and record results again, but only run tests that failed in previous tests (like --errors in headless mode)
SWAKS_TEST_SWAKS=../../swaks PERL5LIB=lib/authen-ntlm-local bin/run-all.pl --winnow

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


--


Test suite status as of 2023-11-03
macOS 13.0.1
 - all tests pass
debian 10.13
 - all tests pass
freebsd 12.1-STABLE
 - some network/socket tests intermittently fail because freebsd doesn't free the socket up fast enough from the previous test
 - _options-output/01250, 01260, 01270, 01280 all currently fail because --help gets formatted slightly differently on freebsd
windows
 - unknown, not making everything run clean on windows a priority for the next release

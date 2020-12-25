
run-tests.pl - run a suite of tests
run-all.pl   - run all tests from all suites (or, with --errors, only errors from previous run)
check-env.pl - make sure the environment is suitable for executing the tests (see environment/tooling below for requirements)
runenv       - convenience script which sets TEST_SWAKS and PERL5LIB before executing the actual test script.  The version
               checked in to version control has the most-common values.  It can be edited locally to test different values, but
               different values should not be committed.
runenv.bat   - same as runenv, but specific to Windows.

--



environment/tooling:
	swaks MUST be in your path.
		- TEST_SWAKS environment variable can be set to an explicit swaks to avoid looking up in PATH
		- on Windows, swaks MUST be named swaks.pl
	perl MUST be in your path.
	Capture::Tiny perl module MUST be installed
	Text::Diff perl module needs MUST installed
	Proc::Background perl module MUST be installed
	all "optional" perl modules MUST be installed to run the test suite (that is, `swaks --support` must show every option supported)
	TEST_SERVER environment variable MUST be set to a suitable path to run transaction tests.  The runenv default should be suitable everywhere
	PAGER environment variable SHOULD be set to make displaying of diffs most useful (can just set it to 'less')
		- except on Windows, see below
	TEST_AUTOCAT environment variable MAY be set to 1 to force run-tests.pl to display a diff automatically on test failure
	SWAKS_EDITOR environment variable MAY be set to a text editor.  When (e)dit is chosen, the test scriopt will be opened using this variable
		- If SWAKS_EDITOR is not set, VISUAL and then EDITOR will also be checked

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

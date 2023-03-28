use 5.010001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'App::swaks',
    VERSION           => '20201014.0',
    ABSTRACT          => 'Swiss Army Knife for SMTP testing',
    AUTHOR            => 'John Jetmore <jj33@pobox.com>',
    LICENSE           => 'gpl',
    EXE_FILES         => ['swaks'],
);

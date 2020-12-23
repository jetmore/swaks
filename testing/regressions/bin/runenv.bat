
@echo off

set PATH=C:\Strawberry\perl\bin;%PATH%
copy ..\..\swaks var\swaks.pl >NUL
set TEST_SWAKS=var\swaks.pl
set TEST_SERVER=../server/smtp-server.pl
rem set PAGER=more
rem this can be really convenient when you have a ton of small changes to accept so you don't have to quit out of the pager
rem set PAGER=cat

call %*

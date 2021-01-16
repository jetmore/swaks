
@echo off

set PATH=C:\Strawberry\perl\bin;%PATH%
copy ..\..\swaks var\swaks.pl >NUL
set SWAKS_TEST_SWAKS=var\swaks.pl
set SWAKS_TEST_SERVER=../server/smtp-server.pl
rem set SWAKS_TEST_PAGER=more

rem Either or both of these can be really convenient when you have a ton of small changes to accept.
rem Setting SWAKS_TEST_PAGER to cat means you don't have to quit out of a pager when viewing the diff
rem export SWAKS_TEST_PAGER=cat
rem Setting SWAKS_TEST_AUTOCAT to 1 means that everytime a test fails, the diff is auto-catted for review
rem export SWAKS_TEST_AUTOCAT=1

call %*

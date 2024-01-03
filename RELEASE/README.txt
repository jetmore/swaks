------------------------------
INSTALL
------------------------------
Swaks is designed to be a self contained script.  It should run on any system
that has Perl installed, although its capabilities may be limited by which
modules are installed.

To get a view of what Swaks can and cannot do on a given system, run:

    swaks --support

Swaks will evaluate the installed perl modules and inform you of any
missing functionality, and how to get that functionality.  Example output:

    === AUTH CRAM-MD5 supported
    === AUTH CRAM-SHA1 supported
    === AUTH DIGEST-MD5 supported
    *** AUTH NTLM not available: requires Authen::NTLM
    === Basic AUTH supported
    === Date Manipulation supported
    === High Resolution Timing supported
    === IPv4/v6 Socket Transport supported
    === Legacy IPv4 Socket Transport supported
    === Legacy IPv4/v6 Socket Transport supported
    === Local Hostname Detection supported
    === MX Routing supported
    === Netrc Credentials supported
    === Pipe Transport supported
    === TLS supported
    === UNIX Socket Transport supported

------------------------------
Documentation
------------------------------
Check the following files
    README.txt
        This file.  Contains install notes, references to other
        files, and major changes for this release
    doc/ref.txt
        The text version of the --help output
    doc/Changes.txt
        All changes to Swaks
    doc/recipes.txt
        Hints, tips, tricks that don't fit in the reference

------------------------------
Source
------------------------------
The Swaks source code is available at https://github.com/jetmore/swaks

------------------------------
Communication
------------------------------

Ways to stay up to date on new releases:
               Homepage: https://jetmore.org/john/code/swaks/
            Online Docs: https://jetmore.org/john/code/swaks/latest/doc/ref.txt
                         https://jetmore.org/john/code/swaks/faq.html
          Announce List: send mail to updates-swaks@jetmore.net
            Project RSS: https://jetmore.org/john/blog/c/swaks/feed/
                Twitter: https://www.twitter.com/SwaksSMTP
                   Help: send questions to proj-swaks@jetmore.net
Bugs / Feature Requests: https://github.com/jetmore/swaks/issues

------------------------------
Authorship
------------------------------
Swaks is crafted with love by John Jetmore from the cornfields of
Indiana, United States of America.

------------------------------
License
------------------------------
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

A full copy of this license should be available in the LICENSE.txt file.

------------------------------
Change Summary
------------------------------
v20240103.0
  New Features:
    * Added --cc and --bcc options
    * Numerous TLS debugging and verification improvements
      * Debug output contains whether a client cert was requested and whether
        one was sent
      * Add new options --tls-verify-ca and --tls-verify-host to differentiate
        between types of certificate verification (--tls-verify does both)
      * Add --tls-target option to allow setting of hostname to be used in
        hostname verification.  This is useful in some inet debugging situations
        and required to do hostname verification with --socket or --pipe
      * Add --tls-chain (#60, initial implementation by Wolfgang Karall-Ahlborn)
      * Add --tls-get-peer-chain option (analogous to --tls-get-peer-cert, #73)
      * Certificate debug now includes all client and peer certs, it a chain
        was used (#73)
      * Certificate debug now includes notAfter, commonName, and subjectAltName
  Notable Changes:
    * --output-file, --output-file-stderr, and --output-file-stdout now truncate
      the specified file if it already exists
    * Documentation improvements
    * Extensive test harness improvements
    * Add new stop-point XCLIENT-HELO to address lack of specificity when
      mixing XCLIENT usage with the HELO stop-point
    * Add new stop-point PROXY
    * Use IO::Socket::IP by default.  Will still use IO::Socket::INET/INET6
      to cover transition, but this is deprecated and will be removed in the
      future (#43)
    * TLS session debug information is now printed even if we decide not to
      continue the session (eg for failed verification)
    * Previously-deprecated functionality to allow some options to be either
      a filename or a literal string has been removed.  Using the '@' sigil is
      now the only was to specify file contents
    * Previously-deprecated -g option removed
  Notable Bugs Fixed:
    * TLS certificate verification did not always work.  It should now

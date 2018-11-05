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
    *** AUTH DIGEST-MD5 not available: requires Authen::SASL
    *** AUTH NTLM not available: requires Authen::NTLM
    === Basic AUTH supported
    === Date Manipulation supported
    === High Resolution Timing supported
    === Local Hostname Detection supported
    === MX Routing supported
    === Pipe Transport supported
    === Socket Transport supported
    === TLS supported

------------------------------
Documentation
------------------------------
Check the following files
    README.txt
        This file.  Contains install notes, references to other
        files, and major changes for this release
    doc/Changes.txt
        All changes to Swaks
    doc/ref.txt
        The text version of the --help output
    doc/recipes.txt
        Hints, tips, tricks that don't fit in the reference

------------------------------
Communication
------------------------------
The main Swaks website is currently http://jetmore.org/john/code/swaks/

Ways to stay up to date on new releases:
      Homepage: http://jetmore.org/john/code/swaks/
   Online Docs: http://jetmore.org/john/code/swaks/latest/doc/ref.txt
                http://jetmore.org/john/code/swaks/faq.html
 Announce List: send mail to updates-swaks@jetmore.net
   Project RSS: http://jetmore.org/john/blog/c/swaks/feed/
       Twitter: http://www.twitter.com/SwaksSMTP
          Help: send questions to proj-swaks@jetmore.net

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
v20181104.0
  New Features:
    * Added --dump-mail option.
    * Added --xclient-delim, --xclient-destaddr, --xclient-destport,
      --xclient-no-verify, and --xclient-before-starttls options.
  Notable Changes:
    * XCLIENT can now send multiple XCLIENT requests.  Because of this,
      --xclient and --xclient-ATTR values are no longer merged into one
      string.  This breaks previously documented behavior.
    * Numerous improvements to the output of --dump and --dump-as-body,
      including the ability to limit output by section, layout improvements,
      adding missing options to output, and fixing bugs.
  Notable Bugs Fixed:
    * Fixed bug preventing Proxy from working with --tls-on-connect.
    * XCLIENT is now sent after STARTTLS to match with Postfix's expectations.
    * Fixed bug which could allow mail sending to proceed without a valid
      recipient.
    * Replacing a multi-line header via --header or --h-HEADER now replaces
      the entire header, not just the first line.
    * The option for specifying the local port was documented as --local-port
      but implemented as --lport.  Both are now documented and implemented.
    * Fixed two bugs which prevented interactions between --dump,
      --auth-hide-password, --dump-as-body, and --dump-as-body-shows-password
      from producing consistent output.

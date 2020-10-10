# Swaks - Swiss Army Knife for SMTP

Swaks is a featureful, flexible, scriptable, transaction-oriented SMTP test tool written and maintained by [John Jetmore][john_jetmore].  It is free to use and licensed under the GNU GPLv2. Features include:

* SMTP extensions including TLS, authentication, pipelining, PROXY, PRDR, and XCLIENT
* Protocols including SMTP, ESMTP, and LMTP
* Transports including UNIX-domain sockets, internet-domain sockets (IPv4 and IPv6), and pipes to spawned processes
* Completely scriptable configuration, with option specification via environment variables, configuration files, and command line

The official project page is <https://jetmore.org/john/code/swaks/>.

## Download

The latest version of Swaks is **20201010.0** ([announcement][release_announce]), which can be downloaded as a [package][release_package] or a [standalone script][release_script].

See the [installation page][installation_page] for details on installing in multiple environments.

There is also a [versions page][versions_page] which lists every released version of Swaks, complete with changelogs and download links.

## Documentation

The reference documentation from the latest release, which includes quick-start examples, is available as [plain text][plain_doc] and [rendered][rendered_doc].  The documentation from each release is available from the [versions page][versions_page].  There is also an [Occasionally Asked Questions][oaq] document.

## Communications

Feedback and meaningful questions about how to use Swaks are welcome. However, since Swaks is only maintained by a single person as a hobby, there is no guarantee of a timely response.

### Release Notification

* [Send a mail][updates_email]. You will receive notifications of new releases via email. No other email will ever be sent to this list.
* [Follow @SwaksSMTP][twitter] on twitter. Very rarely contains non-release content.
* [Blog][blog]. Swaks-specific blog category ([RSS available][blog_rss]). Very rarely contains non-release content.

### Help and Feedback

* [Issues][issues] - Open an issue for feature requests and bugs.
* [Contact the author][contact_email] - suggestion, tips, patches, feedback, critiques always welcome.

## License

[GNU GPLv2][license]

[john_jetmore]: https://jetmore.org/john/
[plain_doc]: https://jetmore.org/john/code/swaks/latest/doc/ref.txt
[versions_page]: https://jetmore.org/john/code/swaks/versions.html
[installation_page]: https://jetmore.org/john/code/swaks/installation.html
[license]: https://choosealicense.com/licenses/gpl-2.0/
[oaq]: https://jetmore.org/john/code/swaks/faq.html
[twitter]: https://twitter.com/SwaksSMTP
[updates_email]: mailto:updates-swaks@jetmore.net
[contact_email]: mailto:proj-swaks@jetmore.net
[issues]: https://github.com/jetmore/swaks/issues
[blog]: https://www.jetmore.org/john/blog/c/swaks/
[blog_rss]: https://www.jetmore.org/john/blog/c/swaks/feed/
[release_announce]: https://www.jetmore.org/john/blog/2020/10/swaks-release-20201010-0-available/
[release_package]: https://jetmore.org/john/code/swaks/files/swaks-20201010.0.tar.gz
[release_script]: https://jetmore.org/john/code/swaks/files/swaks-20201010.0/swaks
[rendered_doc]: https://github.com/jetmore/swaks/blob/v20201010.0/doc/base.pod

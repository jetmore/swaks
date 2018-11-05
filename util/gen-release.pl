#!/usr/bin/perl

use Pod::Text;
use Pod::Html;
use FindBin qw($Bin);


my $home = "$Bin/..";
my $release_d = "$home/RELEASE";
my $release = shift || die "Need release\n";

my $pod_blob = '';

print "Building swaks... ";
open(O, ">$release_d/swaks") || die "can't write to $release_d/swaks: $!\n";
open(I, "<$home/swaks") || die "can't read from $home/swaks\n";
while (<I>) {
  # build_version("DEVRELEASE"
  s|build_version\("DEVRELEASE"|build_version("$release"|g;
  print O;
}
close(I);
open(I, "<$home/doc/base.pod") || die "can't read from $home/doc/base.pod: $!\n";
while (<I>) {
  s|DEVRELEASE|$release|g;
  $pod_blob .= $_;
  print O;
}
close(I);
print O "__END__\n";
close(O);
print "done\n";

print "Building ref.pod... ";
open(O, ">$release_d/doc/ref.pod") || die "Can't write to ref.pod: $!\n";
print O $pod_blob;
close(O);
print "done\n";

print "Building ref.txt... ";
my $pod2text = Pod::Text->new();
$pod2text->parse_from_file("$release_d/doc/ref.pod", "$release_d/doc/ref.txt");
print "done\n";

print "Building recipes.pod... ";
open(I, "<$home/doc/recipes.pod") || die "can't read from $home/doc/recipes.pod: $!\n";
open(O, ">$release_d/doc/recipes.pod") || die "Can't write to recipes.pod: $!\n";
while (<I>) {
  print O;
}
close(O);
close(I);
print "done\n";

print "Building recipes.txt... ";
$pod2text->parse_from_file("$release_d/doc/recipes.pod", "$release_d/doc/recipes.txt");
print "done\n";

# ugh, the resulting html sucks, skip it
#print "Building ref.html... ";
#pod2html("--infile=$release_d/doc/ref.pod",
#         "--outfile=$release_d/doc/ref.html",
#         "--title=swaks reference, release $release");
#print "done\n";

my @lines = ();
print "Building Changes.txt\n";
open(I, "<$home/Changes") || die "Couldn't open $home/Changes: $!\n";
open(O, ">$release_d/doc/Changes.txt") || die "can't write Changes.txt: $!";
while (<I>) {
  if (/^\S/) {
    push (@lines, $_);
  } else {
    $lines[-1] .= $_;
  }
}
print O reverse(@lines);
close(O);
close(I);


print <<EOM;

******  Update Changes to include release, if not already there (rerun script if you had to add it)
******  UPDATE RELEASE/README.txt
******  UPDATE doc/index.html, doc/version.html

SVN COMMIT to put /RELEASE/ into SVN

TAG RELEASE:
  svn copy http://svn.jetmore.org/swaks/trunk/RELEASE http://svn.jetmore.org/swaks/tags/r-$release
EXPORT AND PACKAGE RELEASE (fulton):
  cd ~/jetmore.org/john/code/swaks/files
  release=20170101.0
  svn export http://svn.jetmore.org/swaks/tags/r-$release swaks-$release
  tar -cvf - swaks-$release | gzip > swaks-$release.tar.gz
  cd /home/jetmore/jetmore.org/john/code/swaks/
  svn export --force http://svn.jetmore.org/swaks/trunk/doc/index.html
  svn export --force http://svn.jetmore.org/swaks/trunk/doc/versions.html
  /bin/rm -f latest latest.tar.gz
  ln -s files/swaks-$release ./latest
  ln -s files/swaks-$release.tar.gz ./latest.tar.gz

blog
twitter
email list
EOM

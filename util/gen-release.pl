#!/usr/bin/perl

use File::Copy;
use Pod::Text;
# use Pod::Html;
use FindBin qw($Bin);


my $home = "$Bin/..";
my $release_d = "$home/RELEASE";
my $app_d     = "$home/App-swaks";
my $release = shift || die "Need release\n";

if (-d $release_d) {
  my $oldDir = "$release_d." . time();
  move($release_d, $oldDir) || die "Can't move($release_d, $oldDir): $!\n";
}

print "Creating " . getRelative($release_d, $home) . "... ";
mkdir($release_d) || die "Can't mkdir $release_d: $!\n";
print "done\n";

print "Creating " . getRelative("$release_d/doc", $home) . "... ";
mkdir("$release_d/doc") || die "Can't mkdir $release_d/doc: $!\n";
print "done\n";

print "Building " . getRelative("$release_d/swaks", $home) . "... ";
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
chmod(0755, "$release_d/swaks") || die "Couldn't chmod $release_d/swaks: $!\n";
print "done\n";

my $pod2text = Pod::Text->new();
foreach my $file (["$home/doc/base.pod",         "$release_d/doc/ref.txt"],
                  ["$home/doc/recipes.pod",      "$release_d/doc/recipes.txt"])
{
  print "Building " . getRelative($file->[1], $home) . "... ";
  $pod2text->parse_from_file($file->[0], $file->[1]);
  print "done\n";
}

# ugh, the resulting html sucks, skip it
#print "Building ref.html... ";
#pod2html("--infile=$release_d/doc/ref.pod",
#         "--outfile=$release_d/doc/ref.html",
#         "--title=swaks reference, release $release");
#print "done\n";

# The live Changes file gets updates at the end.  The RELEASE/doc/Changes.txt file is newest-first
my @lines = ();
print "Building " . getRelative("$release_d/doc/Changes.txt", $home) . "... ";
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
print "done\n";

print "Copying  " . getRelative("$release_d/LICENSE.txt", $home) . "... ";
copy("$home/LICENSE", "$release_d/LICENSE.txt") || die "can't copy($home/LICENSE, $release_d/LICENSE.txt) : $!";
print "done\n";

print "Copying  " . getRelative("$release_d/README.txt", $home) . "... ";
copy("$home/doc/README-template.txt", "$release_d/README.txt") || die "can't copy($home/doc/README-template.txt, $release_d/README.txt) : $!";
print "done\n";

print "Copying  " . getRelative("$app_d/LICENSE.txt", $home) . "... ";
copy("$home/LICENSE", "$app_d/LICENSE") || die "can't copy($home/LICENSE, $release_d/LICENSE) : $!";
print "done\n";

print "Copying  " . getRelative("$app_d/swaks", $home) . "... ";
copy("$release_d/swaks", "$app_d/swaks") || die "can't copy($release_d/swaks, $app_d/swaks) : $!";
print "done\n";
chmod(0755, "$app_d/swaks") || die "Couldn't chmod $app_d/swaks: $!\n";

exit;

sub getRelative {
  my $fullPath = shift;
  my $basePath = shift;

  if ($basePath !~ m|/$|) {
    $basePath .= '/';
  }

  $fullPath =~ s|^$basePath||;

  return($fullPath);
}

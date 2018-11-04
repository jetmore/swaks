#!/usr/bin/perl

use Pod::Text;
use FindBin qw($Bin);

my $refFile = "$Bin/../tmp/working-ref.txt";
my $podFile = "$Bin/../doc/base.pod";

print "Building $refFile from $podFile... ";
my $pod2text = Pod::Text->new();
$pod2text->parse_from_file("$podFile", "$refFile");

open(I, "<$refFile") || die "Couldn't open $refFile to read: $!\n";
my $text = join('', <I>);
close(I);

open(O, ">$refFile") || die "Couldn't open $refFile to write: $!\n";
print O "###################################################################\n",
        "# This is an unofficial version of ref.txt.  It is not tracked in\n",
        "# git and will not be used anywhere except for mid-dev-cycle\n",
        "# reference.  Any changes made to it will be lost.\n",
        "# To regenerate when base.pod changes: \n",
        "#      util/gen-working-ref.txt\n",
        "###################################################################\n",
        "\n",
        $text;

print "done\n";

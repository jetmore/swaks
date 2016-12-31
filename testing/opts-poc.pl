#!/usr/bin/perl

use Getopt::Long;

# Getopt::Long::Configure("bundling_override");
# GetOptions(%options) || exit(1);
# GetOptions(\%Opts, 'ComponentID=i', 'Device=s', 'Help|?') or pod2usage(-verbose => 1, -indent => 2);

%options = (
	'length|l' => \$length,
	'width|w'  => \$width,
	'height|h' => \$height,
	'from|f:s'   => \$from
);

# with bundleing override turned on, --foo is "unknown option", -foo is "-f set, value = "oo"
Getopt::Long::Configure("bundling_override");

GetOptions(%options) || exit(1);

print "\$length = $length\n";
print "\$width  = $width\n";
print "\$height = $height\n";
print "\$from   = $from\n";

# swaks recommendation

# http://perldoc.perl.org/Getopt/Long.html#Simple-options

# turn off ALL bundling.  There are very few single-letter opts in swaks that DON'T require arguments.
# therefore, turn bundling off so that:

# -tls-foo => unknown option -tls-foo, instead of assuming it's --tls, option="-foo"

# go through options and make sure every option is documented
#  ... every variation is documented

# look at my code to add prefixes - always use "--", not "-"


# Also, strongly recomment turning off auto_abbrev.

# go through every option and make sure it has a sensical short form

# Also look into "auto_version"
# also look into "auto_help"
# also look at GetOptionsFromArray
# also look at GetOptionsFromString
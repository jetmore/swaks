#!/usr/bin/env perl

use strict;

while (<>) {
	s|\r|\\r|g;
	s|\n|\\n\n|g;
	print;
}

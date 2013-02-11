#!/usr/bin/perl
use strict;
use warnings;

# This is a script used by the build system, to normalize the dependencies that get out of GCC.
# It allows calling the make from subdirectories, since the paths to the files are different then.
# So we replace the variable parts of paths with the $(O) make variable.

die "Not enough arguments. And you're not supposed to call it directly anyway.\n" unless @ARGV == 2;
my ($O, $in) = @ARGV;

$O .= '/';
$O =~ s/^\.\///; # GCC is so nice it removes the first dot. Or is it make? Whatever, but we don't have it there.
$O =~ s/\./\\./g;

open my $input, '<', $in or die "Could not read $in ($!)\n";
while (<$input>) {
	s#^$O(\S)#\$(O)/$1#;
	s# $O([^/\\ ])# \$(O)/$1#g;
	print;
}

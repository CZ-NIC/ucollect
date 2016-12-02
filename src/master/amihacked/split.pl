#!/usr/bin/perl

# Sort the lines of input into several files, according to the IP at the front.
# This helps parallelize the jsonize step (we can't split the IP address into two
# groups, but if all the ones with the same prefix are together, this won't happen).
use common::sense;

mkdir "split";
my $last;
my $f;

while (<>) {
	my ($prefix) = /^(..)/;
	$prefix =~ s/:/_/g;
	if ($last ne $prefix) {
		close $f if $f;
		open $f, '|-', "gzip -1 >split/$prefix.csv.gz" or die "Failed to open split/$prefix.csv: $!\n";
		$last = $prefix;
	}
	print $f $_;
}

close $f;

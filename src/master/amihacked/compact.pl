#!/usr/bin/perl
use common::sense;

# Sum consecutive lines with the same ip, date and kind together. Used to make
# the primary export smaller (the db doesn't guarantee the similar lines to be
# together, but they still often are).

my ($ip, $date, $cnt, $kind);

sub flush() {
	if ($ip) {
		print "$ip,$date,$cnt,$kind\n";
		undef $ip;
	}
}

while (<>) {
	chomp;
	my ($new_ip, $new_date, $new_cnt, $new_kind) = split /,/;
	if (($new_ip ne $ip) or ($new_date ne $date) or ($new_kind ne $kind)) {
		flush;
		($ip, $date, $cnt, $kind) = ($new_ip, $new_date, $new_cnt, $new_kind);
	} else {
		$cnt += $new_cnt;
	}
}
flush;

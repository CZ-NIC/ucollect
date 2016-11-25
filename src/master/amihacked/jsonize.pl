#!/usr/bin/perl
# This script takes series of CSV lines about attacks and constructs
# corresponding JSON records for them. It expects the lines of one
# IP address to be consequtive.
#
# The columns are:
# * IP address
# * date
# * kind of attack
#
# The produced lines contain the IP address and JSON description. The
# json object is indexed by the kind of attack and the date. This
# holds the count of attacks on the day.
#
# eg:
#  192.0.2.1	{"telnet": {"2015-10-05": 5}}
#
# All IPv6 attackers are aggregated into their /64 ranges as well, in addition
# to individual records.
use common::sense;
use JSON qw(encode_json);
use NetAddr::IP;

my $last_ip;

my $object;
my %nets;

sub flush() {
	return unless defined $last_ip;
	print $last_ip->canon(), "\t", encode_json $object, "\n";
	undef $object;
}

my $ip6_strange = NetAddr::IP->new("f000::/8");
my $ip4_strange = NetAddr::IP->new("224.0.0.0/4");

while (<>) {
	chomp;
	my ($ip, $date, $cnt, $kind) = split /,/;
	$ip = NetAddr::IP->new($ip) or die "Bad IP: $ip\n";
	# Skip addresses that are not interesting:
	# • Localhost
	# • Private IPv4 ranges (RFC 1918)
	# • Multicast IPv4 ranges
	# • f* IPv6 addresses (there are several kinds of strange addresses, like fe* local ones, ff*multicast ones, etc.
	next if $ip->is_local() or $ip->is_rfc1918() or $ip->within($ip4_strange) or $ip->within($ip6_strange);
	if ($last_ip ne $ip) {
		flush;
		$last_ip = $ip;
	}
	$object->{$kind}->{$date} += $cnt;
	if ($ip->version() == 6) {
		my $net = NetAddr::IP->new($ip->canon(), 64)->network();
		# Make sure it is stringified
		$nets{$net->canon()}->{$kind}->{$date} += $cnt;
	}
}

flush;

while (my ($net, $obj) = each %nets) {
	print "$net/64\t", encode_json $obj, "\n";
}

#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use List::Util qw(sum);
use Socket qw(inet_pton AF_INET AF_INET6);
use Net::Whois::IP qw(whoisip_query);
use Data::Dumper;

# First connect to the database
my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

# We want to know what IP addresses are out of the line. We count how many different IP addresses there are for each batch and set a limit on how small count of IP addresses can be based on that.
my $ip_hist = $dbh->selectall_hashref('SELECT COUNT(*) AS cnt, request, ip, batch, MIN(host) AS host FROM pings JOIN ping_requests ON ping_requests.id = request WHERE ip IS NOT NULL GROUP BY request, ip, batch', [qw(request batch ip)]);

my %reports;

for my $request (sort { $a <=> $b } keys %$ip_hist) {
	my $req_data = $ip_hist->{$request};
	my $any = [values %{[values %$req_data]->[0]}]->[0];
	for my $batch (sort keys %$req_data) {
		my $batch_data = $req_data->{$batch};
		my (%cnt, %ip_cnt, %limit);
		# We keep separate counts and limits for each family. Otherwise, the few odd clients that are IPv6-only will just always stand out.
		while (my ($ip, $record) = each %$batch_data) {
			for my $family (AF_INET, AF_INET6) {
				if (inet_pton($family, $ip)) {
					$record->{family} = $family;
					$cnt{$family} += $record->{cnt};
					$ip_cnt{$family} ++;
				}
			}
		}
		$limit{$_} = $cnt{$_} / ($ip_cnt{$_} ** 2) for keys %cnt;
		while (my ($ip, $record) = each %$batch_data) {
			if ($record->{cnt} < $limit{$record->{family}}) {
				push @{$reports{$any->{host}}->{$ip}}, {
					limit => $limit{$record->{family}},
					count => $record->{cnt},
					batch => $batch,
					family => $record->{family},
				};
			}
		}
	}
}

my %whitelists = (
	'^AKAMAI-(\d+|PA|ARIN-\d+)$' => 'Akamai',
	'^AIBV$' => 'Akamai',
	'^AKAMAI$' => 'Akamai',
	'^EU-AKAMAI-\d+$' => 'Akamai',
	'^TWITTER-NETWORK$' => 'Twitter',
	'^GOOGLE$' => 'Google',
);

for my $host (sort keys %reports) {
	print "Minority IP addresses on $host:\n";
	my $ips = $reports{$host};
	my %whitelist_ips;
	IP:
	while (my ($ip, $details) = each %$ips) {
		my $whois = whoisip_query($ip);
		my %whois = map { lc $_ => $whois->{$_} } keys %$whois;
		my $netname = $whois{netname};
		for my $rex (keys %whitelists) {
			if ($netname =~ /$rex/) {
				$whitelist_ips{$whitelists{$rex}} ++;
				next IP;
			}
		}
		print "• $ip\n";
		print "  hostname: " . gethostbyaddr(inet_pton($details->[0]->{family}, $ip), $details->[0]->{family}) . "\n";
		print "  owner: '$netname'\n";
		print "  batches: " . (join ', ', map "$_->{batch}($_->{count})", @$details) . "\n";
	}
	if (%whitelist_ips) {
		print "• Whitelisted owners: " . (join ', ', map "$_($whitelist_ips{$_})", keys %whitelist_ips) . "\n";
	}
}

# Extract weak ciphers and protocols
my $ciph = $dbh->selectall_arrayref('SELECT request, batch, cipher, proto, COUNT(*) AS count, MIN(host) AS host, MIN(port) AS port FROM certs JOIN cert_requests on request = cert_requests.id GROUP BY request, batch, cipher, proto');

my %weak_ciphs;
my %weak_proto;

my %strong_proto = (
	TLSv1 => 1,
	'TLSv1.1' => 1,
	'TLSv1.2' => 1,
);

my %strong_ciph = (
	AES128 => 1,
	AES256 => 1,
	AES384 => 1,
);

my %strong_sig = (
	SHA => 1,
	SHA256 => 1,
	SHA384 => 1,
);

for my $crecord (@$ciph) {
	my ($request, $batch, $cipher, $proto, $count, $host, $port) = @$crecord;
	if (!$strong_proto{$proto}) {
		push @{$weak_proto{$proto}}, $crecord;
	}
	my $orig_cipher = $cipher;
	my $fs = ($cipher =~ s/^(ECDHE|DHE)-//) ? $1 : undef;
	my $asym = ($cipher =~ s/^(ECDSA|DSA|RSA)-//) ? $1 : undef;
	$cipher =~ s/^(DES-CBC3|[^-]+)-//;
	my $ciph = $1;
	my $chain = ($cipher =~ s/^(GCM)-//) ? $1 : undef;
	my $sig = ($cipher =~ s/^(SHA\d*|MD5)$//) ? $1 : undef;
	if (length $cipher) {
		warn "Badly parsed cipher string, have a rest: $cipher for $host:$port ($count clients at $batch)\n";
		next;
	}
	if (!$strong_ciph{$ciph} || !$strong_sig{$sig}) {
		push @{$weak_ciphs{$orig_cipher}}, $crecord;
	}
}

sub ciph_hosts($) {
	my ($records) = @_;
	my %hosts;
	for my $record (@$records) {
		my ($request, $batch, $cipher, $proto, $count, $host, $port) = @$record;
		push @{$hosts{"$host:$port"}}, "$batch ‒ $count";
	}
	print map "  ◦ $_\n", sort keys %hosts;
	# TODO: Do we want some more info?
}

if (%weak_proto) {
	print "Weak protocols:\n";
	for my $proto (sort keys %weak_proto) {
		print "• $proto\n";
		ciph_hosts $weak_proto{$proto};
	}
}

if (%weak_ciphs) {
	print "Weak ciphers:\n";
	for my $ciph (sort keys %weak_ciphs) {
		print "• $ciph\n";
		ciph_hosts $weak_ciphs{$ciph};
	}
}

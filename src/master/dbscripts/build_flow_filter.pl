#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST);
use Data::Dumper;

# First connect to the database
my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

my $blacklist_file = $cfg->val('blacklist', 'file');
my %blacklist;
open my $black_open, '<', $blacklist_file or die "Couldn't read blacklist from $blacklist_file: $!\n";
while (my $line = <$black_open>) {
	chomp $line;
	$line =~ s/#.*//;
	$line =~ s/^\s*//;
	$line =~ s/\s*$//;
	next unless length $line;
	my ($err, @addresses) = getaddrinfo $line, 0;
	die "Couldn't resolve $line: $err\n" if $err;
	for my $addr (@addresses) {
		my ($err, $ip) = getnameinfo $addr->{addr}, NI_NUMERICHOST;
		die "Couldn't print address for $line: $err\n" if $err;
		$blacklist{$ip} = 1;
	}
}
close $black_open;

# Read the IPset rules and extract addresses
open my $ipsets, '-|', 'wget', 'https://api.turris.cz/firewall/turris-ipsets', '-q', '-O', '-' or die "Couldn't download ip set rules: $!\n";
my %data;
my %ranges;
while (<$ipsets>) {
	next if /^\s*(#.*|)$/; # Skip comments and empty lines
	next if /^create /; # Creations of sets are not interesting for us
	if (/^add\s+\S+\s+(\S+)/) {
		my ($ip, $port, $range) = ($1, '', '');
		($ip, $port) = ($1, "P$3") if $ip =~ /(.*),(udp|tcp):(\d+)/;
		($ip, $range) = ($1, $2) if $ip =~ /(.*)\/(\d+)/;
		if ($ip =~ /:/) {
			$range = '' if $range == 128;
		} else {
			$range = '' if $range == 32;
		}
		if (length $range) {
			$ranges{"$ip,$range"} = 1;
		} else {
			$data{$port}->{$ip} = 1;
		}
	}
}
close $ipsets;
die "Wget failed with $?" if $?;

open my $graylist, '-|', 'wget', 'https://www.turris.cz/greylist-data/greylist-latest.csv', '-q', '-O', '-' or die "Couldn't download graylist: $!\n";
my $header = <$graylist>;
while (<$graylist>) {
	my ($ip) = split /,/;
	$data{''}->{$ip} = 1;
}
close $graylist;
die "Wget failed with $?" if $?;

# Extract addresses from the anomalies
my $an_stm = $dbh->prepare('SELECT DISTINCT value, type FROM anomalies WHERE relevance_count >= ?');
$an_stm->execute($cfg->val('anomalies', 'client_treshold'));
while (my ($ip, $ano_type) = $an_stm->fetchrow_array) {
	my ($port, $type) = ('', '');
	if ($ano_type =~ /[lLbB]/) {
		my $cp_ip = $ip;
		die "Invalid compound address $cp_ip" unless ($ip, $type, $port) = ($ip =~ /^(.*)(:|->)(\d+)$/);
	}
	$ip =~ s/^\[(.*)\]$/$1/;
	$type = 'P' if $type eq ':';
	if ($type eq '->') { # For local-port anomalies, we're going to watch all communication with the remote end
		$port = '';
		$type = '';
	}
	$data{$type . $port}->{$ip} = 1;
}

# Drop IP addresses from specific rules if they are in the generic one
while (my ($port, $ips) = each %data) {
	delete @{$data{$port}}{keys %blacklist};
	next unless $port;
	# Magic. See perldoc perldata, talk about hash slices.
	delete @{$data{$port}}{keys %{$data{''}}};
}

# Combine the filter string
my $comma;
my $filter = '|(';
for my $port (sort keys %data) {
	my $ips = $data{$port};
	next unless %$ips;
	$filter .= $comma;
	$comma = ',';
	my $close;
	if ($port =~ /^(.)(\d+)$/) {
		$filter .= "&($1($2),";
		$close = ')';
	}
	$filter .= 'I(';
	$filter .= join ',', sort keys %$ips;
	$filter .= ')';
	$filter .= $close;
}
$filter .= ')';

my $range_filter;
my @interesting_remote_ports = (
	21,	# ftp
	22,	# ssh
	23,	# telnet
	25,	# smtp
	109,	# pop2
	110,	# pop3
	123,	# ntp
	143,	# imap
	161,	# snmp
	194,	# irc
	445,	# smb
	465,	# smtps
	587,	# submission
	993,	# imaps
	994,	# ircs
	995,	# pop3s
	1443,	# mssql
	3306,	# mysql
	3389,	# rdp
	5060,	# sip
	5432,	# postgres
	5900,	# vnc
	8767,	# teamspeak
);
my $ports = 'P(' . (join ',', @interesting_remote_ports) . ')';
if (%ranges) {
	$range_filter = "|($ports,D(addresses)," . join ',', map "R($_)", sort keys %ranges;
	$range_filter .= ')';
} else {
	$range_filter = "|($ports,D(addresses))";
}

my %flattened;
while (my ($port, $ips) = each %data) {
	$port =~ s/^P//;
	@flattened{map {
			my $result = $_;
			if ($port) {
				$result = "[$_]" if /:/;
				$result = "$result:$port";
			}
			$result;
		} keys %$ips} = values %$ips;
}

my ($max_epoch) = $dbh->selectrow_array("SELECT COALESCE(MAX(epoch), 1) FROM flow_filters WHERE filter = 'addresses'");

my $existing = $dbh->selectall_arrayref("
SELECT
	flow_filters.address
FROM
	flow_filters
JOIN
	(SELECT
		MAX(epoch) AS epoch,
		MAX(version) AS version,
		address
	FROM
		flow_filters
	WHERE
		filter = 'addresses' AND
		epoch = ?
	GROUP BY
		address)
	AS selector
ON
	flow_filters.version = selector.version AND
	flow_filters.epoch = selector.epoch AND
	flow_filters.address = selector.address
WHERE
	flow_filters.add AND
	filter = 'addresses'", undef, $max_epoch);

my %existing = map { $_->[0] => 1 } @$existing;

# Compute simetric differences between previous and current versions
my %to_delete = %existing;
delete @to_delete{keys %flattened}; # Delete everything that was except the things that still are to be
my %to_add = %flattened;
delete @to_add{keys %existing}; # Add everything that shall be but didn't exist before

my $version = (time / 30) % (2**32); # We won't run it more often than once a minute. Half a minute resolution should be enough to provide security that'll never generate two same versions.

my $mod = $dbh->prepare("INSERT INTO flow_filters (filter, epoch, version, add, address) VALUES ('addresses', ?, ?, ?, ?)");
$mod->execute($max_epoch, $version, 1, $_) for keys %to_add;
$mod->execute($max_epoch, $version, 0, $_) for keys %to_delete;

# Check if the filter is different. If not, just keep the old one.
my ($cur_filter) = $dbh->selectrow_array("SELECT value FROM config WHERE name = 'filter-diff' AND plugin = 'flow'");
if ($cur_filter ne $range_filter) {
	$dbh->do("UPDATE config SET value = ? WHERE name = 'filter-diff' AND plugin = 'flow'", undef, $range_filter);
	$dbh->do("UPDATE config SET value = ? WHERE name = 'version' AND plugin = 'flow'", undef, $version);
}
$dbh->commit;

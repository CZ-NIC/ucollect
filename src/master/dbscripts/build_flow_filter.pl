#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use Data::Dumper;

# First connect to the database
my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

# Read the IPset rules and extract addresses
open my $ipsets, '-|', 'wget', 'https://api.turris.cz/firewall/turris-ipsets', '-q', '-O', '-' or die "Couldn't download ip set rules: $!\n";
my %data;
while (<$ipsets>) {
	next if /^\s*(#.*|)$/; # Skip comments and empty lines
	next if /^create /; # Creations of sets are not interesting for us
	if (/^add\s+\S+\s+(\S+)/) {
		my ($ip, $port) = ($1, '');
		($ip, $port) = ($1, "P$3") if $ip =~ /(.*),(udp|tcp):(\d+)/;
		$data{$port}->{$ip} = 1;
	}
}
close $ipsets;
die "Wget failed with $?" if $?;

# Extract addresses from the anomalies
my $an_stm = $dbh->prepare('SELECT DISTINCT value FROM anomalies WHERE relevance_count >= ?');
$an_stm->execute($cfg->val('anomalies', 'client_treshold'));
while (my ($ip) = $an_stm->fetchrow_array) {
	my ($port, $type) = ('', '');
	($ip, $type, $port) = ($1, $2, $3) if $ip =~ /^(.*)(:|->)(\d+)$/;
	$ip =~ s/^\[(.*)\]$/$1/;
	$type = 'P' if $type eq ':';
	$type = 'p' if $type eq '->';
	$data{$type . $port}->{$ip} = 1;
}

# Drop IP addresses from specific rules if they are in the generic one
while (my ($port, $ips) = each %data) {
	next unless $port;
	# Magic. See perldoc perldata, talk about hash slices.
	delete @{$data{$port}}{keys %{$data{''}}};
}

# Combine the filter string
my $comma;
my $filter;
for my $port (sort keys %data) {
	my $ips = $data{$port};
	next unless %$ips;
	$filter .= $comma;
	$comma = ',';
	my $close;
	if ($port =~ /^(.)(\d+)$/) {
		$filter .= "&($1($2)),";
		$close = ')';
	}
	$filter .= 'I(';
	$filter .= join ',', sort keys %$ips;
	$filter .= ')';
	$filter .= $close;
}

# Check if the filter is different. If not, just keep the old one.
my ($cur_filter) = $dbh->selectrow_array("SELECT value FROM config WHERE name = 'filter' AND plugin = 'flow'");
if ($cur_filter eq $filter) {
	$dbh->rollback;
	exit;
}
$dbh->do("UPDATE config SET value = ? WHERE name = 'filter' AND plugin = 'flow'", undef, $filter);
my $version = time % (2**32);
$dbh->do("UPDATE config SET value = ? WHERE name = 'version' AND plugin = 'flow'", undef, $version);
$dbh->commit;

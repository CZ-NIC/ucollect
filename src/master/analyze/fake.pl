#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;

my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

my %turris_addresses;
open my $addresses, '<', $ARGV[1] or die "Could not read address list '$ARGV[1]': $!\n";
while (my $line = <$addresses>) {
	chomp $line;
	my ($id, $addr) = split /;/, $line;
	$turris_addresses{$addr} = 1;
}
close $addresses;

my $forbidden;

my @private = (
	# Private IPv4
	qr/^10\./,
	(map qr/^172\.$_\./, 16..31),
	qr/^192\.168\./,
	# Link local IPv4
	qr/^169\.254\./,
	# IPv6 private and link local (almost)
	qr/^f[ed]..:/
);

my $bl_stm = $dbh->prepare('SELECT server, remote, clients_total, score_total, mode FROM fake_blacklist');
$bl_stm->execute;
local $\ = "\n";
local $, = ",";
while (my ($server, $remote, @rest) = $bl_stm->fetchrow_array) {
	if ($turris_addresses{$remote}) {
		warn "Address $remote belongs to a turris router\n";
		$forbidden = 1;
		continue;
	}
	if (grep { $remote =~ $_ } @private) {
		warn "Address $remote is private\n";
		$forbidden = 1;
		continue;
	}
	print $server, $remote, @rest;
}

$dbh->rollback;

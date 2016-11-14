#!/usr/bin/perl

# This script adds provided attacker data to the database. It expects
# the data to come in a form:
#
#   ip-address	JSON data
#
# (The separator is a tab)
#
# If -i is provided, the DB is cleaned and new data is inserted. If not,
# the JSONs are summed together.
use common::sense;
use DBI;
use JSON qw(encode_json decode_json);
use Getopt::Long;
use Config::IniFiles;

my $initial;
my $dbini = "db.ini";

GetOptions
	initial => \$initial,
	'dbini=s' => \$dbini
or die "Error parsing parameters\n";

my $cfg = Config::IniFiles->new(-file => $dbini) or die "Failed to read config: @Config::IniFiles::errors\n";
my ($dbname, $dbuser, $dbpass, $dbhost) = map { $cfg->val('amihacked', $_) } qw(db user passwd host);

# Connect to the database. Use the username based authentication (→ no password)
my $dbh = DBI->connect("dbi:Pg:dbname=$dbname" . ($dbhost ? ";host=$dbhost" : ""), $dbuser, $dbpass, {RaiseError => 1, AutoCommit => 0});

my $lookup = $dbh->prepare("SELECT data FROM amihacked_statistics WHERE address = ?");
my $insert = $dbh->prepare("INSERT INTO amihacked_statistics (address, data) VALUES (?, ?)");
my $update = $dbh->prepare("UPDATE amihacked_statistics SET data = ? WHERE address = ?");

# If we want to provide initial data, wipe the original
$dbh->do("TRUNCATE amihacked_statistics") if $initial;

while (<>) {
	chomp;
	my ($addr, $data) = split /\t/;
	my $previous;
	unless ($initial) {
		# Unless we fill the DB with initial data, try to look up previous value
		$lookup->execute($addr);
		($previous) = $lookup->fetchrow_array;
	}
	if ($previous) {
		# Decode both old and new
		my $json_previous = decode_json $previous;
		my $json_data = decode_json $data;
		# Sum them together, fieldwise
		while (my ($date, $date_data) = each %$json_data) {
			while (my ($kind, $cnt) = each %$date_data) {
				# If the field is not there yet, it gets created (including all the necessary levels above it)
				$json_previous->{$date}->{$kind} += $cnt;
			}
		}
		# Store the new value
		$update->execute(encode_json $json_previous, $addr);
	} else {
		# Insert a new value
		$insert->execute($addr, $data);
	}
}
$dbh->commit;

#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;

# First connect to databases
my $cfg = Config::IniFiles->new(-file => $ARGV[0]);

sub connect_db($) {
	my ($kind) = @_;
	my ($host, $db, $user, $passwd) = map { $cfg->val($kind, $_) } qw(host db user passwd);
	return DBI->connect("dbi:Pg:dbname=$db;host=$host", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });
}

my $source = connect_db 'source';
my $destination = connect_db 'destination';

# Synchronize the configuration tables
# We do this by reading all data from both databases and comparing. Ugly, but it works.
my %config_tables = (
	groups => [qw(id name)],
	anomaly_types => [qw(code description)],
	count_types => [qw(ord name description)],
);


while (my($table, $columns) = each %config_tables) {
	print "Syncing config table $table\n";
	# Dump the whole table from both databases
	my $columns_commas = join ', ', @$columns;
	my $select = "SELECT $columns_commas FROM $table";
	my $config_get = sub {
		my ($db) = @_;
		my $array = $db->selectall_arrayref($select);
		my %hash = map { $_->[0] => $_ } @$array;
		($array, \%hash);
	};
	my ($src_arr, $src_hash) = $config_get->($source);
	my ($dst_arr, $dst_hash) = $config_get->($destination);
	# Compare the data from the tables
	my $questions = join ', ', ('?')x@$columns;
	while (my ($id, $row) = each %$src_hash) {
		if (exists $dst_hash->{$id}) {
			# The row is in both tables. Just check that they are the same.
			my $src_row = join '"', @$row;
			my $dst_row = join '"', @{$dst_hash->{$id}};
			die "Mismatched config on table $table with ID $id\n" if $src_row ne $dst_row;
		} else {
			# The row is in source, but not destination. Push it there too.
			$destination->do("INSERT INTO $table ($columns_commas) VALUES ($questions)", undef, @$row);
		}
		# We don't mind rows in destination but not in source. After all, destination is archive.
	}
}

# Migrate anomalies.
# First, look for the newest one stored. They are stored in batches in transaction some time from each other, so we wont lose anything.
my ($max_anom) = $destination->selectrow_array('SELECT COALESCE(MAX(timestamp), TO_TIMESTAMP(0)) FROM anomalies');
print "Getting anomalies newer than $max_anom\n";
# Keep reading and putting it to the other DB
my $store_anomaly = $destination->prepare('INSERT INTO anomalies (from_group, type, timestamp, value, relevance_count, relevance_of, strength) VALUES (?, ?, ?, ?, ?, ?, ?)');
my $get_anomalies = $source->prepare('SELECT from_group, type, timestamp, value, relevance_count, relevance_of, strength FROM anomalies WHERE timestamp > ?');
$get_anomalies->execute($max_anom);
my $count = 0;
$store_anomaly->execute_for_fetch(sub {
        my $data = $get_anomalies->fetchrow_arrayref;
        $count ++ if $data;
        return $data;
});
print "Stored $count anomalies\n";

$source->rollback;
$destination->commit;

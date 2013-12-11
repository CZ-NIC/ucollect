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

# Migrate the counts. We let the source database do the aggregation.
my ($max_count) = $destination->selectrow_array('SELECT COALESCE(MAX(timestamp), TO_TIMESTAMP(0)) FROM count_snapshots');
print "Getting counts newer than $max_count\n";
# Select all the counts for snapshots and expand the snapshots.
# Then join with the groups and generate all pairs count-group for the client it is in the group.
# Then aggregate over the (type, time, group) and produce that.
my $get_counts = $source->prepare('
SELECT
        timestamp, in_group, type, COUNT(*),
        SUM(count), AVG(count), STDDEV(count), MIN(count), MAX(count),
        SUM(size), AVG(size), STDDEV(size), MIN(size), MAX(size)
FROM
        counts
JOIN count_snapshots ON counts.snapshot = count_snapshots.id
JOIN group_members ON count_snapshots.client = group_members.client
WHERE timestamp > ?
GROUP BY timestamp, in_group, type
ORDER BY timestamp, in_group
');
$get_counts->execute($max_count);
my $store_snapshot = $destination->prepare('INSERT INTO count_snapshots (timestamp, from_group) VALUES(?, ?)');
my $store_count = $destination->prepare('
INSERT INTO counts (
        snapshot, type, client_count,
        count_sum, count_avg, count_dev, count_min, count_max,
        size_sum, size_avg, size_dev, size_min, size_max
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
');
my ($last_group, $last_timestamp);
my $snapshot;
my ($snap_count, $stat_count) = (0, 0);
while (my ($timestamp, $in_group, $type, @stats) = $get_counts->fetchrow_array) {
        my $snap_id = "$timestamp/$in_group";
        if ($timestamp ne $last_timestamp or $last_group ne $in_group) {
                $store_snapshot->execute($timestamp, $in_group);
                $snapshot = $destination->last_insert_id(undef, undef, 'count_snapshots', undef);
                $snap_count ++;
                $last_timestamp = $timestamp;
                $last_group = $in_group;
        }
        $store_count->execute($snapshot, $type, @stats);
        $stat_count ++;
}

print "Stored $stat_count count statistics in $snap_count snapshots\n";

# FIXME: This'll need to be updated after #2963 is fixed. We may lose the columns or we may need
# to determine which column to use based on the direction of the packet.
my $get_packets = $source->prepare('
SELECT router_loggedpacket.id, group_members.in_group, router_loggedpacket.time, router_loggedpacket.src_port, router_loggedpacket.src_addr, router_loggedpacket.protocol, router_loggedpacket.count FROM router_loggedpacket
JOIN router_router ON router_loggedpacket.router_id = router_router.id
JOIN group_members ON router_router.client_id = group_members.client
WHERE NOT archived
ORDER BY id
');
print "Getting new firewall packets\n";
$get_packets->execute;
my $store_packet = $destination->prepare('INSERT INTO firewall_packets (time, port, addr, protocol, count) VALUES (?, ?, ?, ?, ?)');
my $packet_group = $destination->prepare('INSERT INTO firewall_groups (packet, for_group) VALUES (?, ?)');
my ($last_id, $id_dest);
$count = 0;
while (my ($id, $group, @data) = $get_packets->fetchrow_array) {
	if ($last_id != $id) {
		$store_packet->execute(@data);
		$last_id = $id;
		$id_dest = $destination->last_insert_id(undef, undef, 'firewall_packets', undef);
		$count ++;
	}
	$packet_group->execute($id_dest, $group);
}
my $archived_count = $source->do('UPDATE router_loggedpacket SET archived = TRUE WHERE NOT archived');
die "Archived $count packets, but marked $archived_count" if $archived_count != $count;
print "Stored $count packets\n";

$destination->commit;
$source->commit;

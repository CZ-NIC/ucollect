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
	activity_types => [qw(id name)],
	clients => [qw(id name)],
	ping_requests => [qw(id host proto amount size)],
	cert_requests => [qw(id host port starttls want_cert want_chain want_details want_params)],
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

$destination->commit;
$source->commit;
undef $destination;
undef $source;

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';

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
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
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
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my $get_packets = $source->prepare('
			SELECT router_loggedpacket.id, group_members.in_group, router_loggedpacket.rule_id, router_loggedpacket.time, router_loggedpacket.direction, router_loggedpacket.remote_port, router_loggedpacket.remote_address, router_loggedpacket.local_port, router_loggedpacket.protocol, router_loggedpacket.count FROM router_loggedpacket
			JOIN router_router ON router_loggedpacket.router_id = router_router.id
			JOIN group_members ON router_router.client_id = group_members.client
			WHERE NOT archived
			ORDER BY id
			');
	print "Getting new firewall packets\n";
	$get_packets->execute;
	my $store_packet = $destination->prepare('INSERT INTO firewall_packets (rule_id, time, direction, port_rem, addr_rem, port_loc, protocol, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
	my $packet_group = $destination->prepare('INSERT INTO firewall_groups (packet, for_group) VALUES (?, ?)');
	my $update_archived = $source->prepare('UPDATE router_loggedpacket SET archived = TRUE WHERE id = ?');
	my ($last_id, $id_dest);
	my $count = 0;
	while (my ($id, $group, @data) = $get_packets->fetchrow_array) {
		if ($last_id != $id) {
			$store_packet->execute(@data);
			$last_id = $id;
			$id_dest = $destination->last_insert_id(undef, undef, 'firewall_packets', undef);
			$count ++;
			$update_archived->execute($id);
		}
		$packet_group->execute($id_dest, $group);
	}
	print "Stored $count packets\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';

	# Get the newest day stored. We'll overwrite this day (we assume there's overlap from the last time we archived).
	my ($max_act) = $destination->selectrow_array('SELECT COALESCE(MAX(activities.date), DATE(TO_TIMESTAMP(0))) FROM activities');
	print "Dropping archived anomalies at $max_act\n";
	$destination->do('DELETE FROM activities WHERE activities.date = ?', undef, $max_act);
	print "Getting activities not older than $max_act\n";
	# Keep reading and putting it to the other DB
	my $store_activity = $destination->prepare('INSERT INTO activities (date, activity, client, count) VALUES (?, ?, ?, ?)');
	my $get_activities = $source->prepare('SELECT DATE(timestamp), activity, client, COUNT(id) FROM activities WHERE DATE(timestamp) >= ? GROUP BY activity, client, DATE(timestamp)');
	$get_activities->execute($max_act);
	my $count = 0;
	$store_activity->execute_for_fetch(sub {
		my $data = $get_activities->fetchrow_arrayref;
		$count ++ if $data;
		return $data;
	});
	print "Stored $count activity summaries\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(ping_stats.batch), TO_TIMESTAMP(0)) FROM ping_stats');
	print "Dropping pings from batch $max_batch\n";
	$destination->do('DELETE FROM ping_stats WHERE ping_stats.batch = ?', undef, $max_batch);
	print "Getting pings not older than $max_batch\n";
	my $store_stat = $destination->prepare('INSERT INTO ping_stats (batch, request, from_group, received, asked, resolved, min, max, avg) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $get_stat = $source->prepare('SELECT batch, request, group_members.in_group, SUM(received), COUNT(1), COUNT(ip), MIN(min), MAX(max), SUM(received * avg) / SUM(received) FROM pings JOIN group_members ON pings.client = group_members.client WHERE batch >= ? GROUP BY batch, request, group_members.in_group');
	$get_stat->execute($max_batch);
	my $stat_cnt = 0;
	$store_stat->execute_for_fetch(sub {
		my $data = $get_stat->fetchrow_arrayref;
		$stat_cnt ++ if $data;
		return $data;
	});
	print "Stored $stat_cnt ping statistics\n";
	print "Getting IP address histograms since $max_batch\n";
	my $store_hist = $destination->prepare('INSERT INTO ping_ips (ping_stat, ip, count) SELECT id, ?, ? FROM ping_stats WHERE batch = ? AND request = ? AND from_group = ?');
	my $get_hist = $source->prepare('SELECT ip, COUNT(DISTINCT pings.client), batch, request, group_members.in_group FROM pings JOIN group_members ON pings.client = group_members.client WHERE batch >= ? GROUP BY request, batch, group_members.in_group, ip');
	my $hist_cnt = 0;
	$get_hist->execute($max_batch);
	$store_hist->execute_for_fetch(sub {
		my $data = $get_hist->fetchrow_arrayref;
		$hist_cnt ++ if $data;
		return $data;
	});
	print "Stored $hist_cnt ping histograms\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(cert_histograms.batch), TO_TIMESTAMP(0)) FROM cert_histograms');
	print "Dropping certificates from batch $max_batch\n";
	$destination->do('DELETE FROM cert_histograms WHERE cert_histograms.batch = ?', undef, $max_batch);
	print "Getting certificates not older than $max_batch\n";
	my $store_hist = $destination->prepare('INSERT INTO cert_histograms (batch, request, from_group, cert, count) VALUES (?, ?, ?, ?, ?)');
	my $get_hist = $source->prepare('SELECT batch, request, in_group, value, count(certs.client) FROM certs JOIN cert_chains ON cert_chains.cert = certs.id JOIN group_members ON group_members.client = certs.client WHERE cert_chains.ord = 0 AND batch >= ? GROUP BY group_members.in_group, certs.request, cert_chains.value, batch');
	my $hist_count = 0;
	$get_hist->execute($max_batch);
	$store_hist->execute_for_fetch(sub {
		my $data = $get_hist->fetchrow_arrayref;
		$hist_count ++ if $data;
		return $data;
	});
	print "Stored $hist_count certificate histograms\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_time) = $destination->selectrow_array('SELECT COALESCE(MAX(bandwidth.timestamp), TO_TIMESTAMP(0)) FROM bandwidth');
	print "Getting bandwidth records newer than $max_time\n";
	my $store_band = $destination->prepare('INSERT INTO bandwidth (timestamp, from_group, win_len, in_min, out_min, in_max, out_max, in_avg, out_avg, in_var, out_var) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $get_band = $source->prepare('SELECT timestamp, in_group, win_len, MIN(input), MIN(output), MAX(input), MAX(output), AVG(input), AVG(output), STDDEV_POP(input), STDDEV_POP(output) FROM (SELECT timestamp, client, win_len, 1000000.0 * in_max / win_len AS input, 1000000.0 * out_max / win_len AS output FROM bandwidth) AS b JOIN group_members ON group_members.client = b.client WHERE timestamp > ? GROUP BY timestamp, in_group, win_len');
	my $band_count = 0;
	$get_band->execute($max_time);
	$store_band->execute_for_fetch(sub {
		my $data = $get_band->fetchrow_arrayref;
		$band_count ++ if $data;
		return $data;
	});
	print "Stored $band_count bandwidth records\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my $max_time = $destination->selectrow_array('SELECT COALESCE(MAX(flows.tagged_on), TO_TIMESTAMP(0)) FROM flows');
	print "Getting flows tagget after $max_time\n";
	my $store_flow = $destination->prepare('INSERT INTO flows (peer_ip, peer_port, inbound, proto, start, stop, opposite_start, size, count, tag, tagged_on) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $store_group = $destination->prepare('INSERT INTO flow_groups (flow, from_group) VALUES (?, ?)');
	my $get_flows = $source->prepare('SELECT
			group_members.in_group, flows.id, ip_from, ip_to, port_from, port_to, inbound, proto, start, stop, opposite_start, size, count, tag, tagged_on
		FROM
			flows
		JOIN
			groups
		ON
			flows.client = groups.client
		WHERE
			tagged_on > ?
		ORDER BY
			flows.id');
	$get_flows->execute($max_time);
	my ($fid, $dst_fid);
	my ($fcount, $gcount) = (0, 0);
	while (my ($group, $id, $ip_from, $ip_to, $port_from, $port_to, $inbound, @payload) = $get_flows->fetchrow_array) {
		if ($fid != $id) {
			$store_flow->execute($inbound ? ($ip_from, $port_from) : ($ip_to, $port_to), $inbound, @payload);
			$dst_fid = $destination->last_insert_id(undef, undef, 'flows', undef);
			$fcount ++;
			$fid = $id;
		}
		$store_group->execute($dst_fid, $group);
		$gcount ++;
	}
	print "Stored $fcount flows with $gcount group entries\n";
	$source->commit;
	$destination->commit;
}

wait for (1..8);

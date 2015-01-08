#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use List::Util qw(sum);

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
	my $count = -1;
	$store_anomaly->execute_for_fetch(sub {
		$count ++;
		return $get_anomalies->fetchrow_arrayref;
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
			$count ++;
			if ($count % 100000 == 0) {
				print "Packet snapshot at $count\n";
				$destination->commit;
				$source->commit;
			}
			$store_packet->execute(@data);
			$last_id = $id;
			$id_dest = $destination->last_insert_id(undef, undef, 'firewall_packets', undef);
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
	my $count = -1;
	$store_activity->execute_for_fetch(sub {
		$count ++;
		return $get_activities->fetchrow_arrayref;
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
	my $stat_cnt = -1;
	$store_stat->execute_for_fetch(sub {
		$stat_cnt ++;
		return $get_stat->fetchrow_arrayref;
	});
	print "Stored $stat_cnt ping statistics\n";
	print "Getting IP address histograms since $max_batch\n";
	my $store_hist = $destination->prepare('INSERT INTO ping_ips (ping_stat, ip, count) SELECT id, ?, ? FROM ping_stats WHERE batch = ? AND request = ? AND from_group = ?');
	my $get_hist = $source->prepare('SELECT ip, COUNT(DISTINCT pings.client), batch, request, group_members.in_group FROM pings JOIN group_members ON pings.client = group_members.client WHERE batch >= ? GROUP BY request, batch, group_members.in_group, ip');
	my $hist_cnt = -1;
	$get_hist->execute($max_batch);
	$store_hist->execute_for_fetch(sub {
		$hist_cnt ++;
		return $get_hist->fetchrow_arrayref;
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
	my $hist_count = -1;
	$get_hist->execute($max_batch);
	$store_hist->execute_for_fetch(sub {
		$hist_count ++;
		return $get_hist->fetchrow_arrayref;
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
	my $band_count = -1;
	$get_band->execute($max_time);
	$store_band->execute_for_fetch(sub {
		$band_count ++;
		return $get_band->fetchrow_arrayref;
	});
	print "Stored $band_count bandwidth records\n";
	my ($max_time, $cur_time) = $destination->selectrow_array("SELECT COALESCE(MAX(bandwidth_avg.timestamp), TO_TIMESTAMP(0)), CURRENT_TIMESTAMP AT TIME ZONE 'UTC' FROM bandwidth_avg");
	print "Getting bandwidth stats newer than $max_time\n";
	my $store_avg = $destination->prepare('INSERT INTO bandwidth_avg (timestamp, client, bps_in, bps_out) VALUES (?, ?, ?, ?)');
	my $get_avg = $source->prepare("SELECT timestamp, client, in_time, in_bytes, out_time, out_bytes FROM bandwidth_stats WHERE timestamp > ? AND timestamp + INTERVAL '90 minutes' < ?");
	$get_avg->execute($max_time, $cur_time);
	my $avg_cnt = 0;
	while (my ($timestamp, $client, $in_time, $in_bytes, $out_time, $out_bytes) = $get_avg->fetchrow_array) {
		$_ = sum @$_ for ($in_time, $out_time, $in_bytes, $out_bytes);
		$store_avg->execute($timestamp, $client, int($in_bytes / $in_time), int($out_bytes / $out_time));
		$avg_cnt ++;
	}
	print "Stored $avg_cnt bandwidth averages\n";
	print "Getting bandwidth sums newer than $max_time\n";
	my $store_sum = $destination->prepare('INSERT INTO bandwidth_sums (timestamp, from_group, client_count, in_time, out_time, in_bytes, out_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)');
	my $get_sum = $source->prepare("SELECT timestamp, in_group, in_time, out_time, in_bytes, out_bytes FROM bandwidth_stats JOIN group_members ON bandwidth_stats.client = group_members.client WHERE timestamp > ? AND timestamp + '90 minutes' < ? ORDER BY timestamp, in_group");
	$get_sum->execute($max_time, $cur_time);
	my (@in_time, @out_time, @in_bytes, @out_bytes, $cur_group, $cur_timestamp, $client_cnt);
	my ($sum_cnt, $record_cnt) = (0, 0);
	my $submit = sub {
		return unless defined $cur_timestamp;
		$sum_cnt ++;
		$store_sum->execute($cur_timestamp, $cur_group, $client_cnt, \@in_time, \@out_time, \@in_bytes, \@out_bytes);
		undef @in_time;
		undef @out_time;
		undef @in_bytes;
		undef @out_bytes;
		undef $cur_group;
		undef $cur_timestamp;
		undef $client_cnt;
	};
	my $sum = sub {
		my ($dest, $src) = @_;
		$dest->[$_] += $src->[$_] for 0..(scalar @$src - 1);
	};
	while (my ($timestamp, $in_group, $in_time, $out_time, $in_bytes, $out_bytes) = $get_sum->fetchrow_array) {
		$submit->() if ($in_group != $cur_group) or ($timestamp != $cur_timestamp);
		$cur_group = $in_group;
		$cur_timestamp = $timestamp;
		$client_cnt ++;
		$record_cnt ++;
		$sum->(\@in_time, $in_time);
		$sum->(\@out_time, $out_time);
		$sum->(\@in_bytes, $in_bytes);
		$sum->(\@out_bytes, $out_bytes);
	}
	$submit->();
	print "Aggregated $record_cnt bandwidth records to $sum_cnt sums\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my $max_time = $destination->selectrow_array('SELECT COALESCE(MAX(flows.tagged_on), TO_TIMESTAMP(0)) FROM flows');
	print "Getting flows tagged after $max_time\n";
	my $store_flow = $destination->prepare('INSERT INTO flows (peer_ip, peer_port, inbound, tagged_on, proto, start, stop, opposite_start, size, count, tag, seen_start) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $store_group = $destination->prepare('INSERT INTO flow_groups (flow, from_group) VALUES (?, ?)');
	my $get_flows = $source->prepare('SELECT
			group_members.in_group, flows.id, ip_from, ip_to, port_from, port_to, inbound, tagged_on, proto, start, stop, opposite_start, size, count, tag, flows.seen_start
		FROM
			flows
		JOIN
			group_members
		ON
			flows.client = group_members.client
		WHERE
			tagged_on > ?
		ORDER BY
			flows.id');
	$get_flows->execute($max_time);
	print "Flows are flowing\n";
	my ($fid, $dst_fid);
	my ($fcount, $gcount) = (0, 0);
	my $running_count = 0;
	my $last_tagged_on = $max_time;
	while (my ($group, $id, $ip_from, $ip_to, $port_from, $port_to, $inbound, $tagged_on, @payload) = $get_flows->fetchrow_array) {
		if ($fid != $id) {
			$fcount ++;
			$running_count ++;
			if ($running_count > 100000 and $last_tagged_on != $tagged_on) {
				$source->commit;
				$destination->commit;
				print "Flow snapshot at $fcount\n";
			}
			$last_tagged_on = $tagged_on;
			$store_flow->execute($inbound ? ($ip_from, $port_from) : ($ip_to, $port_to), $inbound, $tagged_on, @payload);
			$dst_fid = $destination->last_insert_id(undef, undef, 'flows', undef);
			$fid = $id;
		}
		$store_group->execute($dst_fid, $group);
		$gcount ++;
	}
	print "Stored $fcount flows with $gcount group entries\n";
	$source->commit;
	$destination->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(batch), TO_TIMESTAMP(0)) FROM nat_counts');
	print "Dropping nats from batch $max_batch\n";
	$destination->do('DELETE FROM nat_counts WHERE batch = ?', undef, $max_batch);
	print "Getting nat records not older than $max_batch\n";
	my $store_nat = $destination->prepare('INSERT INTO nat_counts (from_group, batch, v4direct, v4nat, v6direct, v6nat, total) VALUES(?, ?, ?, ?, ?, ?, ?)');
	my $get_nats = $source->prepare('SELECT in_group, batch, COUNT(CASE WHEN nat_v4 = false THEN true END), COUNT(CASE WHEN nat_v4 = true THEN true END), COUNT(CASE WHEN nat_v6 = false THEN true END), COUNT(CASE WHEN nat_v6 = true THEN true END), COUNT(nats.client) FROM nats JOIN group_members ON nats.client = group_members.client WHERE batch >= ? GROUP BY batch, in_group');
	my $nat_count = -1;
	$get_nats->execute($max_batch);
	$store_nat->execute_for_fetch(sub {
		$nat_count ++;
		return $get_nats->fetchrow_arrayref;
	});
	print "Stored $nat_count nat counts\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(batch), TO_TIMESTAMP(0)) FROM spoof_counts');
	print "Dropping spoofed packets from batch $max_batch\n";
	$destination->do('DELETE FROM spoof_counts WHERE batch = ?', undef, $max_batch);
	print "Getting spoof records not older than $max_batch\n";
	my $store_spoof = $destination->prepare('INSERT INTO spoof_counts (from_group, batch, reachable, spoofable) VALUES (?, ?, ?, ?)');
	my $get_spoof = $source->prepare('SELECT in_group, batch, COUNT(CASE WHEN NOT spoofed THEN TRUE END), COUNT(CASE WHEN spoofed AND addr_matches THEN TRUE END) FROM spoof JOIN group_members ON group_members.client = spoof.client WHERE batch >= ? GROUP BY batch, in_group');
	my $spoof_count = -1;
	$get_spoof->execute($max_batch);
	$store_spoof->execute_for_fetch(sub {
		$spoof_count ++;
		return $get_spoof->fetchrow_arrayref;
	});
	print "Stored $spoof_count spoofed groups\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_since) = $destination->selectrow_array("SELECT DATE_TRUNC('hour', COALESCE(MAX(since), TO_TIMESTAMP(0)) - INTERVAL '30 minutes') FROM refused_addrs");
	print "Dropping refused connections since $max_since\n";
	$destination->do('DELETE FROM refused_addrs WHERE since >= ?', undef, $max_since);
	$destination->do('DELETE FROM refused_clients WHERE since >= ?', undef, $max_since);
	my $store_addr = $destination->prepare('INSERT INTO refused_addrs (addr, port, reason, since, until, conn_count, client_count) VALUES (?, ?, ?, ?, ?, ?, ?)');
	my $get_addr = $source->prepare("SELECT address, remote_port, reason, DATE_TRUNC('hour', timestamp) AS since, DATE_TRUNC('hour', timestamp) + INTERVAL '1 hour' AS until, COUNT(1) AS conn_count, COUNT(DISTINCT client) AS client_count FROM refused WHERE timestamp >= ? GROUP BY address, remote_port, reason, DATE_TRUNC('hour', timestamp)");
	my $addr_count = -1;
	$get_addr->execute($max_since);
	$store_addr->execute_for_fetch(sub {
		$addr_count ++;
		return $get_addr->fetchrow_arrayref;
	});
	my $store_client = $destination->prepare('INSERT INTO refused_clients (client, reason, since, until, count) VALUES (?, ?, ?, ?, ?)');
	my $get_client = $source->prepare("SELECT client, reason, DATE_TRUNC('hour', timestamp) AS since, DATE_TRUNC('hour', timestamp) + INTERVAL '1 hour' AS until, COUNT(1) AS count FROM refused WHERE timestamp >= ? GROUP BY client, reason, DATE_TRUNC('hour', timestamp)");
	my $client_count = -1;
	$get_client->execute($max_since);
	$store_client->execute_for_fetch(sub {
		$client_count ++;
		return $get_client->fetchrow_arrayref;
	});
	print "Stored $addr_count refused addresses and $client_count clients\n";
	$destination->commit;
	$source->commit;
	exit;
}

wait for (1..11);

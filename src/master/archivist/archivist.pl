#!/usr/bin/perl
use common::sense;
use DBI;
use DBD::Pg qw(:pg_types); # Import the DBD::Pg::PG_BYTEA constant (and other similar ones)
use Config::IniFiles;
use List::Util qw(sum);
use Date::Format;

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

sub tprint(@) {
	my $date = time2str('%H:%M:%S', time);
	print $date, "\t", @_;
}

while (my($table, $columns) = each %config_tables) {
	tprint "Syncing config table $table\n";
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

my $interesting_groups = $source->selectall_hashref("SELECT id FROM groups WHERE name NOT LIKE 'rand-%' AND name != 'all'", 'id');

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
	tprint "Getting anomalies newer than $max_anom\n";
	# Keep reading and putting it to the other DB
	my $store_anomaly = $destination->prepare('INSERT INTO anomalies (from_group, type, timestamp, value, relevance_count, relevance_of, strength) VALUES (?, ?, ?, ?, ?, ?, ?)');
	my $get_anomalies = $source->prepare('SELECT from_group, type, timestamp, value, relevance_count, relevance_of, strength FROM anomalies WHERE timestamp > ?');
	$get_anomalies->execute($max_anom);
	my $count = -1;
	$store_anomaly->execute_for_fetch(sub {
		$count ++;
		return $get_anomalies->fetchrow_arrayref;
	});
	tprint "Stored $count anomalies\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	# Migrate the counts. We let the source database do the aggregation.
	my ($max_count) = $destination->selectrow_array('SELECT COALESCE(MAX(timestamp), TO_TIMESTAMP(0)) FROM count_snapshots');
	tprint "Getting counts newer than $max_count\n";
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

	tprint "Stored $stat_count count statistics in $snap_count snapshots\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';

	# We get the maximum time of a packet in the destination and
	# read the packets in the source from that time on. But we don't
	# do it until the current time, but only some time before the maximum.
	# This way, we won't lose any packets if we assume that no worker
	# runs a batch for longer that the given amount of time, therefore
	# the packets won't arrive too late.
	my ($loc_max) = $source->selectrow_array("SELECT MAX(time) - INTERVAL '3 hours' FROM router_loggedpacket");
	my ($rem_max) = $destination->selectrow_array('SELECT COALESCE(MAX(time), TO_TIMESTAMP(0)) FROM firewall_packets');
	tprint "Going to store firewall logs between $rem_max and $loc_max\n";
	# Get the packets. Each packet may have multiple resulting lines,
	# for multiple groups it is in. Prefilter the groups, we are not
	# interested in the random ones. We still have the 'all' group
	# in here, which ensures we have at least one line for the packet
	# (we could solve it by some kind of outer join, but the condition
	# at the WHERE part would get complicated, handling NULL columns).
	my $get_packets = $source->prepare("
			SELECT router_loggedpacket.id, group_members.in_group, router_loggedpacket.rule_id, router_loggedpacket.time, router_loggedpacket.direction, router_loggedpacket.remote_port, router_loggedpacket.remote_address, router_loggedpacket.local_port, router_loggedpacket.protocol, router_loggedpacket.count, router_loggedpacket.tcp_flags FROM router_loggedpacket
			JOIN router_router ON router_loggedpacket.router_id = router_router.id
			JOIN group_members ON router_router.client_id = group_members.client
			JOIN groups ON group_members.in_group = groups.id
			WHERE time > ? AND time <= ? AND groups.name NOT LIKE 'rand-%'
			ORDER BY id
			");
	tprint "Getting new firewall packets\n";
	$get_packets->execute($rem_max, $loc_max);
	my $store_packet = $destination->prepare('INSERT INTO firewall_packets (rule_id, time, direction, port_rem, addr_rem, port_loc, protocol, count, tcp_flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $packet_group = $destination->prepare('INSERT INTO firewall_groups (packet, for_group) VALUES (?, ?)');
	my ($last_id, $id_dest);
	my $count = 0;
	while (my ($id, $group, @data) = $get_packets->fetchrow_array) {
		if ($last_id != $id) {
			$count ++;
			if ($count % 100000 == 0) {
				$destination->commit;
			}
			$store_packet->execute(@data);
			$last_id = $id;
			$id_dest = $destination->last_insert_id(undef, undef, 'firewall_packets', undef);
		}
		if ($interesting_groups->{$group}) { # Filter out the rest of uninteresting groups
			$packet_group->execute($id_dest, $group);
		}
	}
	tprint "Stored $count packets\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';

	# Get the newest day stored. We'll overwrite this day (we assume there's overlap from the last time we archived).
	my ($max_act) = $destination->selectrow_array('SELECT COALESCE(MAX(activities.date), DATE(TO_TIMESTAMP(0))) FROM activities');
	tprint "Dropping archived anomalies at $max_act\n";
	$destination->do('DELETE FROM activities WHERE activities.date = ?', undef, $max_act);
	tprint "Getting activities not older than $max_act\n";
	# Keep reading and putting it to the other DB
	my $store_activity = $destination->prepare('INSERT INTO activities (date, activity, client, count) VALUES (?, ?, ?, ?)');
	my $get_activities = $source->prepare('SELECT DATE(timestamp), activity, client, COUNT(id) FROM activities WHERE DATE(timestamp) >= ? GROUP BY activity, client, DATE(timestamp)');
	$get_activities->execute($max_act);
	my $count = -1;
	$store_activity->execute_for_fetch(sub {
		$count ++;
		return $get_activities->fetchrow_arrayref;
	});
	tprint "Stored $count activity summaries\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(ping_stats.batch), TO_TIMESTAMP(0)) FROM ping_stats');
	tprint "Dropping pings from batch $max_batch\n";
	$destination->do('DELETE FROM ping_stats WHERE ping_stats.batch = ?', undef, $max_batch);
	tprint "Getting pings not older than $max_batch\n";
	my $store_stat = $destination->prepare('INSERT INTO ping_stats (batch, request, from_group, received, asked, resolved, min, max, avg) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $get_stat = $source->prepare('SELECT batch, request, group_members.in_group, SUM(received), COUNT(1), COUNT(ip), MIN(min), MAX(max), SUM(received * avg) / SUM(received) FROM pings JOIN group_members ON pings.client = group_members.client WHERE batch >= ? GROUP BY batch, request, group_members.in_group');
	$get_stat->execute($max_batch);
	my $stat_cnt = -1;
	$store_stat->execute_for_fetch(sub {
		$stat_cnt ++;
		return $get_stat->fetchrow_arrayref;
	});
	tprint "Stored $stat_cnt ping statistics\n";
	tprint "Getting IP address histograms since $max_batch\n";
	my $store_hist = $destination->prepare('INSERT INTO ping_ips (ping_stat, ip, count) SELECT id, ?, ? FROM ping_stats WHERE batch = ? AND request = ? AND from_group = ?');
	my $get_hist = $source->prepare('SELECT ip, COUNT(DISTINCT pings.client), batch, request, group_members.in_group FROM pings JOIN group_members ON pings.client = group_members.client WHERE batch >= ? GROUP BY request, batch, group_members.in_group, ip');
	my $hist_cnt = -1;
	$get_hist->execute($max_batch);
	$store_hist->execute_for_fetch(sub {
		$hist_cnt ++;
		return $get_hist->fetchrow_arrayref;
	});
	tprint "Stored $hist_cnt ping histograms\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(cert_histograms.batch), TO_TIMESTAMP(0)) FROM cert_histograms');
	tprint "Dropping certificates from batch $max_batch\n";
	$destination->do('DELETE FROM cert_histograms WHERE cert_histograms.batch = ?', undef, $max_batch);
	tprint "Getting certificates not older than $max_batch\n";
	my $store_hist = $destination->prepare('INSERT INTO cert_histograms (batch, request, from_group, cert, count) VALUES (?, ?, ?, ?, ?)');
	my $get_hist = $source->prepare('SELECT batch, request, in_group, value, count(certs.client) FROM certs JOIN cert_chains ON cert_chains.cert = certs.id JOIN group_members ON group_members.client = certs.client WHERE cert_chains.ord = 0 AND batch >= ? GROUP BY group_members.in_group, certs.request, cert_chains.value, batch');
	my $hist_count = -1;
	$get_hist->execute($max_batch);
	$store_hist->execute_for_fetch(sub {
		$hist_count ++;
		return $get_hist->fetchrow_arrayref;
	});
	tprint "Stored $hist_count certificate histograms\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_time) = $destination->selectrow_array('SELECT COALESCE(MAX(bandwidth.timestamp), TO_TIMESTAMP(0)) FROM bandwidth');
	tprint "Getting bandwidth records newer than $max_time\n";
	my $store_band = $destination->prepare('INSERT INTO bandwidth (timestamp, from_group, win_len, in_min, out_min, in_max, out_max, in_avg, out_avg, in_var, out_var) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $get_band = $source->prepare('SELECT timestamp, in_group, win_len, MIN(input), MIN(output), MAX(input), MAX(output), AVG(input), AVG(output), STDDEV_POP(input), STDDEV_POP(output) FROM (SELECT timestamp, client, win_len, 1000000.0 * in_max / win_len AS input, 1000000.0 * out_max / win_len AS output FROM bandwidth) AS b JOIN group_members ON group_members.client = b.client WHERE timestamp > ? GROUP BY timestamp, in_group, win_len');
	my $band_count = -1;
	$get_band->execute($max_time);
	$store_band->execute_for_fetch(sub {
		$band_count ++;
		return $get_band->fetchrow_arrayref;
	});
	tprint "Stored $band_count bandwidth records\n";
	my ($max_time, $cur_time) = $destination->selectrow_array("SELECT COALESCE(MAX(bandwidth_avg.timestamp), TO_TIMESTAMP(0)), CURRENT_TIMESTAMP AT TIME ZONE 'UTC' FROM bandwidth_avg");
	tprint "Getting bandwidth stats newer than $max_time\n";
	my $store_avg = $destination->prepare('INSERT INTO bandwidth_avg (timestamp, client, bps_in, bps_out) VALUES (?, ?, ?, ?)');
	my $get_avg = $source->prepare("SELECT timestamp, client, in_time, in_bytes, out_time, out_bytes FROM bandwidth_stats WHERE timestamp > ? AND timestamp + INTERVAL '90 minutes' < ?");
	$get_avg->execute($max_time, $cur_time);
	my $avg_cnt = 0;
	while (my ($timestamp, $client, $in_time, $in_bytes, $out_time, $out_bytes) = $get_avg->fetchrow_array) {
		$_ = sum @$_ for ($in_time, $out_time, $in_bytes, $out_bytes);
		$store_avg->execute($timestamp, $client, int($in_bytes / $in_time), int($out_bytes / $out_time));
		$avg_cnt ++;
	}
	tprint "Stored $avg_cnt bandwidth averages\n";
	tprint "Getting bandwidth sums newer than $max_time\n";
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
	tprint "Aggregated $record_cnt bandwidth records to $sum_cnt sums\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my $max_time = $destination->selectrow_array('SELECT COALESCE(MAX(biflows.tagged_on), TO_TIMESTAMP(0)) FROM biflows');
	my $get_times = $source->prepare('SELECT DISTINCT tagged_on FROM biflows WHERE tagged_on > ? ORDER BY tagged_on');
	tprint "Getting flows times tagged after $max_time\n";
	$get_times->execute($max_time);
	my $store_flow = $destination->prepare('INSERT INTO biflows (ip_remote, port_remote, port_local, tagged_on, proto, start_in, stop_in, start_out, stop_out, size_in, count_in, size_out, count_out, tag, seen_start_in, seen_start_out) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	my $store_group = $destination->prepare('INSERT INTO biflow_groups (biflow, from_group) VALUES (?, ?)');
	# Pre-filter the results so they don't contain the rand-% groups. But we keep the 'all'
	# group in yet. This ensures we get every biflows at least once (otherwise we would
	# have to juggle with outer joins. This is simlpler and less error prone, without
	# too much overhead.
	my $get_flows = $source->prepare("SELECT
			group_members.in_group, biflows.id, ip_remote, port_remote, port_local, tagged_on, proto, start_in, stop_in, start_out, stop_out, size_in, count_in, size_out, count_out, tag, biflows.seen_start_in, biflows.seen_start_out
		FROM
			biflows
		JOIN
			group_members
		ON
			biflows.client = group_members.client
		JOIN
			groups
		ON
			group_members.in_group = groups.id
		WHERE
			tagged_on = ?
		AND
			groups.name NOT LIKE 'rand-%'
		ORDER BY
			biflows.id");
	my ($fid, $dst_fid);
	my ($fcount, $gcount) = (0, 0);
	while (my ($cur_time) = $get_times->fetchrow_array) {
		$get_flows->execute($cur_time);
		while (my ($group, $id, @payload) = $get_flows->fetchrow_array) {
			if ($fid != $id) {
				$fcount ++;
				$store_flow->execute(@payload);
				$dst_fid = $destination->last_insert_id(undef, undef, 'biflows', undef);
				$fid = $id;
			}
			if ($interesting_groups->{$group}) {
				$store_group->execute($dst_fid, $group);
				$gcount ++;
			}
		}
		$source->commit;
		$destination->commit;
	}
	tprint "Stored $fcount flows with $gcount group entries\n";
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(batch), TO_TIMESTAMP(0)) FROM nat_counts');
	tprint "Dropping nats from batch $max_batch\n";
	$destination->do('DELETE FROM nat_counts WHERE batch = ?', undef, $max_batch);
	tprint "Getting nat records not older than $max_batch\n";
	my $store_nat = $destination->prepare('INSERT INTO nat_counts (from_group, batch, v4direct, v4nat, v6direct, v6nat, total) VALUES(?, ?, ?, ?, ?, ?, ?)');
	my $get_nats = $source->prepare('SELECT in_group, batch, COUNT(CASE WHEN nat_v4 = false THEN true END), COUNT(CASE WHEN nat_v4 = true THEN true END), COUNT(CASE WHEN nat_v6 = false THEN true END), COUNT(CASE WHEN nat_v6 = true THEN true END), COUNT(nats.client) FROM nats JOIN group_members ON nats.client = group_members.client WHERE batch >= ? GROUP BY batch, in_group');
	my $nat_count = -1;
	$get_nats->execute($max_batch);
	$store_nat->execute_for_fetch(sub {
		$nat_count ++;
		return $get_nats->fetchrow_arrayref;
	});
	tprint "Stored $nat_count nat counts\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_batch) = $destination->selectrow_array('SELECT COALESCE(MAX(batch), TO_TIMESTAMP(0)) FROM spoof_counts');
	tprint "Dropping spoofed packets from batch $max_batch\n";
	$destination->do('DELETE FROM spoof_counts WHERE batch = ?', undef, $max_batch);
	tprint "Getting spoof records not older than $max_batch\n";
	my $store_spoof = $destination->prepare('INSERT INTO spoof_counts (from_group, batch, reachable, spoofable) VALUES (?, ?, ?, ?)');
	my $get_spoof = $source->prepare('SELECT in_group, batch, COUNT(CASE WHEN NOT spoofed THEN TRUE END), COUNT(CASE WHEN spoofed AND addr_matches THEN TRUE END) FROM spoof JOIN group_members ON group_members.client = spoof.client WHERE batch >= ? GROUP BY batch, in_group');
	my $spoof_count = -1;
	$get_spoof->execute($max_batch);
	$store_spoof->execute_for_fetch(sub {
		$spoof_count ++;
		return $get_spoof->fetchrow_arrayref;
	});
	tprint "Stored $spoof_count spoofed groups\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_since) = $destination->selectrow_array("SELECT DATE_TRUNC('hour', COALESCE(MAX(since), TO_TIMESTAMP(0)) - INTERVAL '90 minutes') FROM refused_addrs");
	tprint "Dropping refused connections since $max_since\n";
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
	tprint "Stored $addr_count refused addresses and $client_count clients\n";
	$destination->commit;
	$source->commit;
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my %sessions;
	my $get_commands = $source->prepare('SELECT ssh_commands.id, start_time, end_time, login, password, remote, remote_port, ts, success, command FROM ssh_commands JOIN ssh_sessions ON ssh_commands.session_id = ssh_sessions.id WHERE NOT archived');
	my $mark_command = $source->prepare('UPDATE ssh_commands SET archived = TRUE WHERE id = ?');
	my $store_command = $destination->prepare('INSERT INTO ssh_commands (session, timestamp, success, command) VALUES (?, ?, ?, ?)');
	# Make sure the params are considered the correct type.
	# bind_param does two things here:
	# * Sets the value of the parameter to NULL (which we'll override by calling execute with a new value).
	# * Sets the data type for the column (which stays across the future calls to bind_param or execute).
	$store_command->bind_param(4, undef, { pg_type => DBD::Pg::PG_BYTEA });
	my $get_session = $destination->prepare('SELECT id, end_time FROM ssh_sessions WHERE start_time = ? AND login = ? AND password = ?');
	$get_session->bind_param(2, undef, { pg_type => DBD::Pg::PG_BYTEA });
	$get_session->bind_param(3, undef, { pg_type => DBD::Pg::PG_BYTEA });
	my $update_session = $destination->prepare('UPDATE ssh_sessions SET end_time = ? WHERE id = ?');
	my $store_session = $destination->prepare('INSERT INTO ssh_sessions (start_time, end_time, login, password, remote, remote_port) VALUES (?, ?, ?, ?, ?, ?) RETURNING id');
	$store_session->bind_param(3, undef, { pg_type => DBD::Pg::PG_BYTEA });
	$store_session->bind_param(4, undef, { pg_type => DBD::Pg::PG_BYTEA });
	$get_commands->execute;
	my $count_commands = 0;
	my $count_sessions = 0;
	while (my ($id, $start, $end, $login, $password, $remote, $remote_port, $time, $success, $command) = $get_commands->fetchrow_array) {
		my $sid = $sessions{$start}->{$login}->{$password};
		if (not defined $sid) {
			$get_session->execute($start, $login, $password);
			if (my ($id, $send) = $get_session->fetchrow_array) {
				$sid = $id;
				$update_session->execute($end, $sid) if ($send ne $end);
			} else {
				$store_session->execute($start, $end, $login, $password, $remote, $remote_port);
				($sid) = $store_session->fetchrow_array;
				$count_sessions ++;
			}
			$sessions{$start}->{$login}->{$password} = $sid;
		}
		$store_command->execute($sid, $time, $success, $command);
		$mark_command->execute($id);
		$count_commands ++;
	}
	$destination->commit;
	$source->commit;
	tprint "Archived $count_sessions SSH sessions and $count_commands commands\n";
	exit;
}

if (fork == 0) {
	my $source = connect_db 'source';
	my $destination = connect_db 'destination';
	my ($max_date) = $destination->selectrow_array("SELECT DATE(COALESCE(MAX(date), TO_TIMESTAMP(0))) FROM fake_attackers");
	$destination->do("DELETE FROM fake_attackers WHERE date >= ?", undef, $max_date);
	my $get_attackers = $source->prepare("SELECT DATE(timestamp), server, remote, COUNT(CASE WHEN event = 'login' THEN true END), COUNT(CASE WHEN event = 'connect' THEN true END) FROM fake_logs WHERE DATE(timestamp) >= ? GROUP BY remote, server, DATE(timestamp)");
	$get_attackers->execute($max_date);
	my $put_attacker = $destination->prepare("INSERT INTO fake_attackers (date, server, remote, attempt_count, connect_count) VALUES (?, ?, ?, ?, ?)");
	my $attackers = -1;
	$put_attacker->execute_for_fetch(sub {
		$attackers ++;
		return $get_attackers->fetchrow_arrayref;
	});
	tprint "Archived $attackers fake attacker stats\n";
	$destination->do("DELETE FROM fake_passwords WHERE timestamp >= ?", undef, $max_date);
	my $get_passwords = $source->prepare("SELECT timestamp, server, remote, name, password, remote_port FROM fake_logs WHERE name IS NOT NULL AND password IS NOT NULL AND event = 'login' AND timestamp >= ?");
	$get_passwords->execute($max_date);
	my $put_password = $destination->prepare("INSERT INTO fake_passwords (timestamp, server, remote, name, password, remote_port) VALUES (?, ?, ?, ?, ?, ?)");
	# Make sure the params are considered the correct type.
	# bind_param does two things here:
	# * Sets the value of the parameter to NULL (which we'll override by calling execute with a new value).
	# * Sets the data type for the column (which stays across the future calls to bind_param or execute).
	$put_password->bind_param(4, undef, { pg_type => DBD::Pg::PG_BYTEA });
	$put_password->bind_param(5, undef, { pg_type => DBD::Pg::PG_BYTEA });
	my $passwords = -1;
	$put_password->execute_for_fetch(sub {
		$passwords ++;
		return $get_passwords->fetchrow_arrayref;
	});
	tprint "Archived $passwords password attempts\n";
	$destination->do("DELETE FROM fake_server_activity WHERE date >= ?", undef, $max_date);
	my $get_activity = $source->prepare("SELECT DATE(timestamp), server, client, COUNT(CASE WHEN event = 'login' THEN true END), COUNT(CASE WHEN event = 'connect' THEN true END) FROM fake_logs WHERE timestamp >= ? GROUP BY DATE(timestamp), server, client");
	$get_activity->execute($max_date);
	my $put_activity = $destination->prepare("INSERT INTO fake_server_activity (date, server, client, attempt_count, connect_count) VALUES (?, ?, ?, ?, ?)");
	my $activity_count = -1;
	$put_activity->execute_for_fetch(sub {
		$activity_count ++;
		return $get_activity->fetchrow_arrayref;
	});
	tprint "Archived $activity_count fake server activity statistics\n";
	$destination->commit;
	$source->commit;
	exit;
}

wait for (1..13);

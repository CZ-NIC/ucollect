package Tagger::Flows;
use common::sense;
use AddrStoreBuild qw($cfg);

sub prepare_tags($@) {
	my ($dbh, @tags) = @_;
	my %tags;
	# Read tags stored in passed files
	for my $fname (@tags) {
		open my $f, '<', $fname or die "Couldn't read $fname: $!\n";
		while (<$f>) {
			chomp;
			next if /^\s*(|#.*)$/; # Empty lines and comments
			next if /^\s*create\s/;
			if (my ($rule, $ip, $port) = /^\s*add\s+(\S+)\s+(\S+),(?:udp|tcp):(\d+)\s*$/) {
				$tags{$ip}->{ports}->{$port} = $rule;
				$tags{$ip}->{values} //= $rule; # Only if there wasn't a global one before
			} elsif (my ($rule, $ip) = /^\s*add\s+(\S+)\s+(\S+)\s*$/) {
				$tags{$ip}->{values} = $rule; # Override one from port-specific
			} else {
				die "Can't parse $_\n";
			}
		}
	}
	# Read the anomalies and use them as tags as well
	my $anomalies = $dbh->prepare('SELECT DISTINCT value, type FROM anomalies WHERE relevance_count >= ?');
	$anomalies->execute($cfg->val('anomalies', 'client_treshold'));
	while (my ($ip, $type) = $anomalies->fetchrow_array) {
		$ip =~ s/(:|->)\d+//;
		next if lc $type eq 'p';
		$tags{$ip}->{values} = "anom-$type";
	}
	# Read the fake server generated blacklist and use it as tags as well
	my $fake_blacklist = $dbh->prepare('SELECT server, remote FROM fake_blacklist_tmp');
	$fake_blacklist->execute;
	while (my ($server, $ip) = $fake_blacklist->fetchrow_array) {
		$tags{$ip}->{values} = "fake-$server";
	}
	print "Prepared flow tags\n";
	return \%tags;
}

sub perform($$) {
	my ($dbh, $tags) = @_;

	my $read = $dbh->prepare('SELECT id, ip_remote, port_remote FROM biflows WHERE tagged_on IS NULL LIMIT 100000');
	my $update = $dbh->prepare('UPDATE biflows SET tag = ?, tagged_on = ? WHERE id = ?');

	my $found = 1;
	my $count = 0;
	while ($found) {
		my $batch = 0;
		my $tstamp = $dbh->selectrow_array("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'");
		$read->execute;
		undef $found;
		while (my ($id, $ip, $port) = $read->fetchrow_array) {
			my $tag = $tags->{$ip}->{ports}->{$port} // $tags->{$ip}->{values} // '?';
			$update->execute($tag, $tstamp, $id);
			$found = 1;
			$count ++;
			$batch ++;
		}
		$dbh->commit;
		print "Done $count flows\n";
		last if $batch < 100000;
	}
}

1;

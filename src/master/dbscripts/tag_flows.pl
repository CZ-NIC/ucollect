#!/usr/bin/perl
use common::sense;
use DBI;

my %tags;

while (<>) {
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

my $dbh = DBI->connect("dbi:Pg:dbname=turris", "tagger", "", { RaiseError => 1, AutoCommit => 0 });
my $read = $dbh->prepare('SELECT id, ip_from, ip_to, port_from, port_to, inbound FROM flows WHERE tag IS NULL LIMIT 100000');
my $update = $dbh->prepare('UPDATE flows SET tag = ?, tagged_on = ? WHERE id = ?');

my $found = 1;
my $count = 0;
while ($found) {
	my $batch = 0;
	my $tstamp = $dbh->selectrow_array("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'");
	$read->execute;
	undef $found;
	while (my ($id, $ip_from, $ip_to, $port_from, $port_to, $inbound) = $read->fetchrow_array) {
		my ($ip, $port);
		if ($inbound) {
			($ip, $port) = ($ip_from, $port_from);
		} else {
			($ip, $port) = ($ip_to, $port_to);
		}
		my $tag = $tags{$ip}->{ports}->{$port} // $tags{$ip}->{values} // '?';
		$update->execute($tag, $tstamp, $id);
		$found = 1;
		$count ++;
		$batch ++;
	}
	$dbh->commit;
	print "Done $count\n";
	last if $batch < 100000;
}


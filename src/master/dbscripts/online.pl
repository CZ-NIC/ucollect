#!/usr/bin/perl
use common::sense;
use Term::ANSIColor;
use Date::Parse;
use DBI;

my $dbh = DBI->connect("dbi:Pg:dbname=routers", "ucollect", "", { RaiseError => 1, AutoCommit => 0 });

my $green = color 'bold green';
my $red = color 'bold red';
my $blue = color 'bold blue';
my $reset = color 'reset';

# TODO: This query is probably slower than we would like (especially the second nested
# SELECT, because it goes through a lot of counts data). No idea what this'll do on
# the real DB with thousand of clients, but maybe the DB will handle it. If not, we'll
# see what can be done about it.
my $stmt = $dbh->prepare(<<'ENDSQL');
SELECT
	aggregate.name,
	aggregate.devel_note,
	aggregate.tag,
	aggregate.last,
	activity_types.name,
	sums.all,
	sums.server
FROM (
	SELECT
		clients.id,
		clients.name,
		clients.devel_note,
		clients.tag,
		MAX(activities.timestamp) AS last
	FROM
		clients
	LEFT OUTER JOIN
		activities ON clients.id = activities.client
	GROUP BY clients.id
) AS aggregate
LEFT OUTER JOIN activities ON
	activities.client = aggregate.id
	AND activities.timestamp = aggregate.last
LEFT OUTER JOIN activity_types ON
	activities.activity = activity_types.id
LEFT OUTER JOIN (
	SELECT
		SUM(CASE WHEN (count_types.name = 'All') THEN counts.count ELSE 0 END) as all,
		SUM(CASE WHEN (count_types.name = 'SERVER') THEN counts.size ELSE 0 END) as server,
		count_snapshots.client
	FROM
		counts
	JOIN count_snapshots ON
		 counts.snapshot = count_snapshots.id
	JOIN count_types ON
		 counts.type = count_types.id
	WHERE
		timestamp > NOW() - interval '1 day'
	GROUP BY count_snapshots.client
) AS sums ON
	sums.client = aggregate.id
ORDER BY
	aggregate.tag ASC,
	aggregate.devel_note ASC;
ENDSQL
while (1) {
	my ($online, $offline) = (0, 0);
	$stmt->execute;
	print "${blue}ID\t\t\tStatus\tAct.\tTime\t\t\t\tCount\t\tServer\t\tNote$reset\n";
	my $now = time;
	my $stuck = $now - 3600;
	while (my ($name, $note, $tag, $last, $activity, $pcount, $ssize) = $stmt->fetchrow_array) {
		my $status = (defined $activity && $activity ne 'logout') ? "${green}online" : "${red}offline";
		$last //= '----';
		$activity //= '----';
		$pcount //= '----';
		$ssize //= '----';
		my $pcolor = color 'reset';
		$pcolor = color 'magenta' if $pcount < 1000000;
		$pcolor = color 'red' if $pcount < 1000;
		my $time = str2time($last // '0');
		if ($time <= $stuck) {
			$status = "${red}stuck" unless $status eq "${red}offline";
			$activity = "$red$activity";
		}
		if ($status eq "${green}online") {
			$online ++;
		} else {
			$offline ++;
		}
		printf "%-16s\t%s$reset\t%s\t%-30s\t$pcolor%10s$reset\t%10s\t%s\n", $name, $status, $activity, $last, $pcount, $ssize, $note;
	}
	print "${green}Online:\t\t\t$online\n${red}Offline:\t\t$offline$reset\n";

	$dbh->rollback;
	last if ($ARGV[0] ne '-f');
	sleep 3;
	print "\033[2J";
}

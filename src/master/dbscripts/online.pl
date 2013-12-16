#!/usr/bin/perl
use common::sense;
use Term::ANSIColor;
use Date::Parse;
use Getopt::Long;
use DBI;

my $dbh = DBI->connect("dbi:Pg:dbname=routers", "ucollect", "", { RaiseError => 1, AutoCommit => 0 });

my $green = color 'bold green';
my $red = color 'bold red';
my $blue = color 'bold blue';
my $reset = color 'reset';

my $forever;
my $all;

GetOptions
	forever => \$forever,
	all => \$all
	or die "Bad parameters\n";

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
	activity_types.name
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
ORDER BY
	aggregate.tag ASC,
	aggregate.devel_note ASC;
ENDSQL
while (1) {
	my ($online, $offline) = (0, 0);
	$stmt->execute;
	print "${blue}ID\t\t\tStatus\tAct.\tTime\t\t\t\tNote$reset\n";
	my $now = time;
	my $stuck = $now - 3600;
	while (my ($name, $note, $tag, $last, $activity) = $stmt->fetchrow_array) {
		my $status = (defined $activity && $activity ne 'logout') ? "${green}online" : "${red}offline";
		$activity //= '----';
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
		next unless $all or defined $last;
		$last //= '----';
		printf "%-16s\t%s$reset\t%s\t%-30s\t%10s$reset\t%10s\t%s\n", $name, $status, $activity, $last, $note;
	}
	print "${green}Online:\t\t\t$online\n${red}Offline:\t\t$offline$reset\n";

	$dbh->rollback;
	last if not $forever;
	sleep 15;
	print "\033[2J";
}

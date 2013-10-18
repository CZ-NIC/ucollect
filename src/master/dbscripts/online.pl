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
my ($online, $offline) = (0, 0);

print "${blue}ID\t\t\tStatus\tAct.\tTime\t\t\t\tNote$reset\n";
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
$stmt->execute;
my $now = time;
my $stuck = $now - 3600;
while (my ($name, $note, $tag, $last, $activity) = $stmt->fetchrow_array) {
	my $status = (defined $activity && $activity ne 'logout') ? "${green}online" : "${red}offline";
	$last //= '-';
	$activity //= '-';
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
	printf "%-16s\t%s$reset\t%s\t%-30s$reset\t%s\n", $name, $status, $activity, $last, $note;
}

$dbh->rollback;

print "${green}Online:\t\t\t$online\n${red}Offline:\t\t$offline$reset\n";

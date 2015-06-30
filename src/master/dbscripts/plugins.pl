#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use Term::ANSIColor;
use Data::Dumper;
use POSIX;
use utf8;

$ENV{TZ} = 'UTC';

my $name_width = 18;
my $plug_width = 12;
my @ok_colors = (color('bold red'), color('bold green'));
my $reset = color 'reset';

my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

my $plugins = $dbh->selectall_arrayref(<<'ENDSQL');
SELECT
	distinct plugin AS name
FROM
	activity_types
WHERE
	plugin IS NOT NULL
UNION
SELECT
	distinct name
FROM
	active_plugins
ORDER BY
	name
ENDSQL

print ' 'x($name_width - 6), 'Client ';
for my $pname (@$plugins) {
	printf "\%${plug_width}s ", $pname->[0];
}
print "\n";

my $client;
my $line;
my $plug_index;

sub act_color($) {
	my ($time) = @_;
	return color 'bold red' unless defined $time;
	return color 'bold green' if $time <= 30;
	return color 'bold blue' if $time <= 60;
	return color 'bold magenta' if $time <= 720;
	return color 'bold red';
}

sub plug_color($$) {
	my ($active, $status) = @_;
	return color 'reset' unless defined $active;
	return color 'reset' if $active;
	return color 'blue' if $status eq 'allowed';
	return color 'magenta' unless defined $status;
	return color 'red';
}

sub tform($) {
	my ($time) = @_;
	return undef unless defined $time;
	return floor($time / 1440) . "d" if $time > 2880;
	return floor($time / 60) . "h" if $time > 240;
	return $time . "m";
}

my $stmt = $dbh->prepare('SELECT name, last, login > logout, login_time, logout_time, plugin, plug_last, hash, status, active FROM plugin_activity');
$stmt->execute;
while (my ($name, $last, $online, $login, $logout, $plugin, $plug_last, $hash, $status, $active) = $stmt->fetchrow_array) {
	if ($name ne $client) {
		print $line, "\n";
		$online = 1 if (not defined $online) && (defined $last);
		my $ocolor = $ok_colors[$online];
		my $act_color = act_color $last;
		$ocolor = $act_color = $reset unless defined $last;
		printf "%s\%${name_width}s%s ", $ocolor, $name, $reset;
		$line = sprintf "\n %s%8s %s%8s%s ", $act_color, (tform $last) // '--------', $ocolor, (tform ($online ? $login : $logout)) // '--------', $reset;
		$client = $name;
		$plug_index = 0;
	}
	next unless defined $plugin;
	while ($plugin ne $plugins->[$plug_index]->[0]) {
		$plug_index ++;
		print " " x ($plug_width + 1);
		$line .= " " x ($plug_width + 1);
	}
	$hash //= '-' x $plug_width;
	$hash =~ s/(.{$plug_width}).*/$1/;
	print plug_color($active, $status), $hash, $reset, " ";
	$line .= sprintf "%s\%${plug_width}s%s ", act_color $plug_last, tform $plug_last, $reset;
	$plug_index ++;
}

print $line, "\n";

my $stmt = $dbh->prepare(<<'ENDSQL');
SELECT
	COALESCE(active_plugins.name, known_plugins.name) AS name,
	COALESCE(active_plugins.hash, known_plugins.hash) AS hash,
	COALESCE(active_plugins.version, known_plugins.version) AS version,
	COUNT(active_plugins.name) AS count,
	SUM(active::integer) AS active,
	MAX(known_plugins.note) AS note,
	MAX(known_plugins.status) As status
FROM
	active_plugins
	FULL OUTER JOIN known_plugins ON active_plugins.name = known_plugins.name AND active_plugins.hash = COALESCE(known_plugins.hash, active_plugins.hash) AND active_plugins.version = COALESCE(known_plugins.version, active_plugins.version)
GROUP BY
	COALESCE(active_plugins.name, known_plugins.name),
	COALESCE(active_plugins.hash, known_plugins.hash),
	COALESCE(active_plugins.version, known_plugins.version)
ORDER BY
	COALESCE(active_plugins.name, known_plugins.name),
	MAX(known_plugins.note),
	COALESCE(active_plugins.hash, known_plugins.hash),
	COALESCE(active_plugins.version, known_plugins.version);
ENDSQL
$stmt->execute;
my $plugin;
while (my ($name, $hash, $version, $count, $active, $note, $status) = $stmt->fetchrow_array) {
	if ($name ne $plugin) {
		print "\n", $name, "\n", "="x length $name, "\n";
		$plugin = $name;
	}
	my $color = color 'bold green';
	$color = color 'bold blue' unless $count;
	$color = color 'bold magenta' if $status ne "allowed";
	$color = color 'bold red' unless defined $status;
	$status //= 'unknown';
	$version //= '?';
	$note =~ s/.*_ucollect_(\w+)_(\d+)\.so/lib $2/;
	my $count_color = $reset;
	$count_color = color 'bold red' if $status ne 'allowed' and $count;
	printf " • %s(%2s) %s%10s%s %4s/%s%4s%s   %s\n", $hash, $version, $color, $status, $reset, 0+$active, $count_color, 0+$count, $reset, $note;
}

$dbh->rollback;

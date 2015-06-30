#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use Term::ANSIColor;
use Data::Dumper;
use POSIX;

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
	return color 'bold green' if $active;
	return color 'bold blue' if $status eq 'allowed';
	return color 'bold magenta' unless defined $status;
	return color 'bold red';
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

$dbh->rollback;

package AddrStoreBuild;
use common::sense;
use base 'Exporter';
use DBI;
use Config::IniFiles;
use Fcntl ':flock';
use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST);

our @EXPORT = qw(single_instance blacklist_load db_connect addr_store_content $cfg);

# Global, so it stays open for the lifetime of the script
my $lockfile;

# Ensure there's only one instance of the script running. Any following one
# will exit. It is expected the next run of the script will catch up by creating
# slightly larger batch in the DB.
sub single_instance($) {
	my ($lock_file_name) = @_;
	open $lockfile, '>>', $lock_file_name or die "Could not open lock file '$lock_file_name': $!\n";
	flock $lockfile, LOCK_EX | LOCK_NB or exit;
}

our $cfg = Config::IniFiles->new(-file => $ARGV[0]);

# Read the blacklist file, resolve all the names there and provide hashref with addresses
sub blacklist_load() {
	my $blacklist_file = $cfg->val('blacklist', 'file');
	my %blacklist;
	open my $black_open, '<', $blacklist_file or die "Couldn't read blacklist from $blacklist_file: $!\n";

	while (my $line = <$black_open>) {
		# Remove comments and whitespace
		chomp $line;
		$line =~ s/#.*//;
		$line =~ s/^\s*//;
		$line =~ s/\s*$//;
		next unless length $line;

		my ($err, @addresses) = getaddrinfo $line, 0;
		die "Couldn't resolve $line: $err\n" if $err;
		for my $addr (@addresses) {
			my ($err, $ip) = getnameinfo $addr->{addr}, NI_NUMERICHOST;
			die "Couldn't print address for $line: $err\n" if $err;
			$blacklist{$ip} = 1;
		}
	}
	return \%blacklist;
}

my $dbh;

# Create connection to the database and return the handle
sub db_connect() {
	# Already connected. Just reuse the connection.
	return $dbh if $dbh;
	# Make a new connection
	my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
	return $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });
}

# Read the current content of an address store. Return the maximal epoch and a hashref containing the addresses
sub addr_store_content($$$) {
	my ($table, $name_column, $name) = @_;
	my $dbh = db_connect;
	my ($max_epoch) = $dbh->selectrow_array("SELECT COALESCE(MAX(epoch), 1) FROM $table WHERE $name_column = ?", undef, $name);
	my $existing = $dbh->selectall_arrayref("
SELECT
	$table.address
FROM
	$table
JOIN
	(SELECT
		MAX(epoch) AS epoch,
		MAX(version) AS version,
		address
	FROM
		$table
	WHERE
		$name_column = ? AND
		epoch = ?
	GROUP BY
		address)
	AS selector
ON
	$table.version = selector.version AND
	$table.epoch = selector.epoch AND
	$table.address = selector.address
WHERE
	$table.add AND
	$name_column = ?", undef, $name, $max_epoch, $name);
	my %existing = map { $_->[0] => 1 } @$existing;
	return ($max_epoch, \%existing);
}

1;

#!/usr/bin/perl
use common::sense;
use DBI;
use Data::Dumper;

my $dbh = DBI->connect("dbi:Pg:dbname=turris", '', '', { RaiseError => 1, AutoCommit => 0 });

my @levels = (2, 4, 8, 16, 32);
my @groups;
for my $level (@levels) {
	push @groups, map "rand-$level-$_", (1..$level);
}
print Dumper \@groups;

#$dbh->do('INSERT INTO groups (name) VALUES (?)', undef, $_) for @groups;

my $ids = $dbh->selectall_arrayref("SELECT id FROM clients WHERE name LIKE '0000000a%'");

for my $id_row (@$ids) {
	my ($id) = @$id_row;
	#$dbh->do('INSERT INTO group_members (client, in_group) SELECT ?, id FROM groups WHERE name = ?', undef, $id, 'all');
	for my $level (@levels) {
		my $rand = 1 + int(rand($level));
		print "$id into $level-$rand\n";
		die "Rand wrong" if $rand > $level;
		$dbh->do('INSERT INTO group_members (client, in_group) SELECT ?, id FROM groups WHERE name = ?', undef, $id, "rand-$level-$rand");
	}
}

$dbh->commit;

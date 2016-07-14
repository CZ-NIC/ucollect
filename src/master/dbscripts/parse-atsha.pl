#!/usr/bin/perl
use common::sense;
use Data::Dumper;

$/ = "\n\n";
my @input = <STDIN>;

my $slot = 0;
my $tag = 'omnia-proto';
my $start = 3;

print "BEGIN;\n";
print "Be sure to use the atshakeys user.\n";
print "\\q\n";

for my $input (@input) {
	my @data = split /\n/, $input;
	my $name = $data[0];
	my @keys = @data[1..16];
	s/\s//g for @keys;
	my $id = join '', @data[17..18];
	$id =~ s/[: ]//g;
	$id = lc($id);
	my $data = $data[$slot + 1];
	print "INSERT INTO clients (name, passwd, mechanism, slot_id, tag, devel_note) VALUES('$id', '$keys[$slot]', 'A', $slot, '$tag', '$name');\n";
#	print "INSERT INTO groups (name) VALUES('T$start');\n";
	print "INSERT INTO group_members (client, in_group) SELECT clients.id, groups.id FROM clients CROSS JOIN groups WHERE clients.name = '$id' AND groups.name = 'all';\n";
#	print "INSERT INTO group_members (client, in_group) SELECT clients.id, groups.id FROM clients CROSS JOIN groups WHERE clients.name = '$id' AND groups.name = 'turris';\n";
#	print "INSERT INTO group_members (client, in_group) SELECT clients.id, groups.id FROM clients CROSS JOIN groups WHERE clients.name = '$id' AND groups.name = 'T$start';\n";
	$start ++;
}
print "COMMIT;\n";

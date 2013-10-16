#!/usr/bin/perl
use common::sense;
use Data::Dumper;

$/ = "\n\n";
my @input = <STDIN>;

my $slot = 8;
my $tag = 'blackbox';
my $start = 3;

print "BEGIN;\n";

for my $input (@input) {
	my @data = split /\n/, $input;
	my $name = $data[0];
	my @keys = @data[1..16];
	my $id = join '', @data[17..18];
	$id =~ s/[: ]//g;
	$id = lc($id);
	print "INSERT INTO clients (name, passwd, mechanism, slot_id, tag, devel_note) VALUES('$id', '$data[$slot]', 'A', $slot, '$tag', '$name');\n";
	print "INSERT INTO groups (name) VALUES('bb$start');\n";
	print "INSERT INTO group_members (client, in_group) SELECT clients.id, groups.id FROM clients CROSS JOIN groups WHERE clients.name = '$id' AND groups.name = 'all';\n";
	print "INSERT INTO group_members (client, in_group) SELECT clients.id, groups.id FROM clients CROSS JOIN groups WHERE clients.name = '$id' AND groups.name = 'blackbox';\n";
	print "INSERT INTO group_members (client, in_group) SELECT clients.id, groups.id FROM clients CROSS JOIN groups WHERE clients.name = '$id' AND groups.name = 'bb$start';\n";
	$start ++;
}
print "COMMIT;\n";

#!/usr/bin/perl
use common::sense;
use Digest::SHA;
use File::Path;

# FIXME: Get rid of the --no-check-certificate 

my ($pass_file, $url, $tag, @plugins) = @ARGV;

sub parse($) {
	my ($hexes) = @_;
	return map hex, $hexes =~ /(.{2})/g;
}

# Read the compiled-in password
open my $pf, '<', $pass_file or die "Could not read password file $pass_file: $!\n";
my $passwd = <$pf>;
close $pf;
chomp $passwd;
$passwd =~ s/[,{}]//g;
$passwd =~ s/\s//g;
$passwd =~ s/0x//g;

my @passwd = parse $passwd;

# Get versions of packages
open my $packages, '-|', 'wget', '--no-check-certificate', "$url/lists/generic", '-O', '-' or die "Couldn't download package list: $!\n";
my @packages = <$packages>;
close $packages or die "Error downloading package list: $!\n";

my %packages = map {
	my ($name, $version) = split;
	$name => "$url/packages/$name-$version.ipk"
} @packages;

my %paths = map {
	my ($name, $version) = split;
	my $file = $name;
	$file =~ s/-/_/;
	$name => "usr/lib/libplugin_${file}_${version}.so"
} @packages;

for my $plugin (@plugins) {
	system 'wget', '--no-check-certificate', ($packages{$plugin} // die "Package $plugin doesn't exist in the list\n"), '-O', 'package.ipk' and die "Couldn't download package $packages{$plugin}\n";
	system 'tar', 'xf', 'package.ipk' and die "Can't unpack package for $plugin\n";
	system 'tar', 'xf', 'data.tar.gz' and die "Can't unpack data for $plugin\n";
	my $library = $paths{$plugin};
	my $sha = Digest::SHA->new(256);
	$sha->addfile($library);
	my @digest = parse $sha->hexdigest;
	for my $i (0..@passwd - 1) {
		$passwd[$i] ^= $digest[$i];
	}
	rmtree 'usr';
}

my $result = join '', map sprintf("%02X", $_), @passwd;
say "UPDATE clients SET builtin_passwd = '$result' WHERE tag = '$tag';";

#!/usr/bin/perl
use strict;
use warnings;
use Socket qw(PF_INET SOCK_DGRAM pack_sockaddr_in inet_aton);
use Getopt::Long;
use Time::HiRes qw(gettimeofday usleep);

# This script can be used to hammer a device with large amounts of UDP packets.
# It is used to see when the device starts dropping packets and
# performance-check it in that way.
#
# Each $interval seconds a burst of $burst packets is sent, each having $size
# payload (and having a header too).
#
# It sends only over IPv4. It seems unimportant which protocol is used when
# the only purpose is to send many packets.
#
# It is not expected the other side will listen to the packets. They would be
# simply dropped, but any analysis tool will get them with pcap.

# Get the options.
my $port = 12345; # Just arbitrary port. We don't expect the other side to listen there.
my $address = 'localhost'; # Which host to spam
my $burst = 10; # How many packets in each burst
my $size = 100; # Size of the payload of the packet
my $interval = 0.01; # Time between starts of bursts.
my $srccount = 1;

GetOptions
	'port=i' => \$port,
	'address=s' => \$address,
	'burst=i' => \$burst,
	'size=i' => \$size,
	'interval=f' => \$interval,
	'origincount=i' => \$srccount,
or exit 1;

# Some information about how much will be sent.
my $speed = ($size + 20) * 8; # Size of one packet with IP headers, in bits
$speed *= $burst; # Size of one burst
$speed /= $interval; # Size per second
$speed /= (1024 ** 2);
print "Expected throughput: $speed MBits, ", $burst / $interval, " packets/s\n";

# Connect the socket (which only sets the address with UDP packet, but we don't want
# to provide it each time).
my @sockets;
for (0..$srccount) {
	socket(my $socket, PF_INET, SOCK_DGRAM, 0) or die "Could not create socket ($!)\n";
	connect($socket, pack_sockaddr_in($port, inet_aton($address))) or die "Could not connect the UDP socket ($!)\n";
	push @sockets, $socket;
}

# Payload of the packet
my $payload = ' ' x $size;

# Time when the current burst started.
my $start_time = gettimeofday;

# Loop forever. Each loop is one burst of packets.
while (1) {
	# Send burst of packets first.
	for (1..$burst) {
		my $result = send $sockets[int rand $srccount], $payload, 0;
		if (defined $result) {
			if ($result < $size) {
				warn "Packet only $result of $size bytes\n";
			}
		} else {
			# We don't expect the other side to listen, so the 'Connection refused' is expected.
			warn "Error sending packet ($!)\n" unless $! eq 'Connection refused';
		}
	}
	# Wait for the rest of the interval.
	my $time = gettimeofday;
	my $elapsed = $time - $start_time;
	if ($elapsed < $interval) {
		usleep 1000000 * ($interval - $elapsed);
		$time = gettimeofday;
	}
	$start_time = $time;
}

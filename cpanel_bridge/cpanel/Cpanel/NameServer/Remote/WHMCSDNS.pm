package Cpanel::NameServer::Remote::WHMCSDNS;

use strict;
use warnings;

use Cpanel::NameServer::Constants ();
use Cpanel::NameServer::Remote ();
use IO::Socket::UNIX ();
use JSON::PP ();
use Socket qw(SOCK_STREAM);

our @ISA = ('Cpanel::NameServer::Remote');
our $VERSION = '1.0';

my $SOCKET = '/run/whmcs-dns-bridge/bridge.sock';

sub new {
    my ( $class, %opts ) = @_;
    return bless { %opts, name => 'WHMCS-DNS' }, $class;
}

sub _submit {
    my ( $self, $action, $dnsuniqid, $zones, $user ) = @_;
    my $socket = IO::Socket::UNIX->new( Type => SOCK_STREAM, Peer => $SOCKET );
    return ( $Cpanel::NameServer::Constants::QUEUE, "WHMCS-DNS bridge is unavailable: $!" ) if !$socket;

    print {$socket} JSON::PP::encode_json(
        {
            action       => $action,
            dnsuniqid    => $dnsuniqid,
            cpanel_user  => $user || '',
            zones        => $zones,
        }
    ) . "\n";
    shutdown $socket, 1;
    my $line = <$socket>;
    close $socket;
    return ( $Cpanel::NameServer::Constants::QUEUE, 'WHMCS-DNS bridge returned no response' ) if !defined $line;

    my $response = eval { JSON::PP::decode_json($line) };
    return ( $Cpanel::NameServer::Constants::QUEUE, 'WHMCS-DNS bridge returned invalid JSON' ) if !$response;
    return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ) if $response->{'ok'};
    return (
        $response->{'retryable'} ? $Cpanel::NameServer::Constants::QUEUE : $Cpanel::NameServer::Constants::DO_NOT_QUEUE,
        $response->{'error'} || 'WHMCS-DNS bridge rejected the request'
    );
}

sub _single_zone {
    my ( $self, $action, $dnsuniqid, $data ) = @_;
    my $zone = $data->{'zone'} || '';
    $zone =~ s/\.db$//;
    return $self->_submit(
        $action,
        $dnsuniqid,
        [ { zone => $zone, data => ( $data->{'zonedata'} || '' ) } ],
        $data->{'user'} || $data->{'owner'} || ''
    );
}

sub savezone     { my ( $self, $id, $data ) = @_; return $self->_single_zone( 'SAVEZONE',     $id, $data ); }
sub quickzoneadd { my ( $self, $id, $data ) = @_; return $self->_single_zone( 'QUICKZONEADD', $id, $data ); }

sub synczones {
    my ( $self, $id, $data ) = @_;
    my @zones;
    for my $key ( sort grep { /^cpdnszone-/ } keys %{$data} ) {
        my $zone = substr( $key, length 'cpdnszone-' );
        $zone =~ s/\.db$//;
        push @zones, { zone => $zone, data => $data->{$key} };
    }
    return $self->_submit( 'SYNCZONES', $id, \@zones, $data->{'user'} || $data->{'owner'} || '' );
}

# Write-only bridge: cPanel requires these methods even though it does not read zones back from WHMCS-DNS.
sub addzoneconf { return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub removezone  { return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub removezones { return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub getallzones { my ($self) = @_; $self->output(''); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub getips      { my ($self) = @_; $self->output(''); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub getpath     { my ($self) = @_; $self->output(''); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub getzone     { my ($self) = @_; $self->output(''); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub getzonelist { my ($self) = @_; $self->output(''); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub getzones    { my ($self) = @_; $self->output(''); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub zoneexists  { my ($self) = @_; $self->output('0'); return ( $Cpanel::NameServer::Constants::SUCCESS, 'OK' ); }
sub version     { return $VERSION; }

1;

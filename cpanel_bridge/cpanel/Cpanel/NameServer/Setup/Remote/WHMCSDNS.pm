package Cpanel::NameServer::Setup::Remote::WHMCSDNS;

use strict;
use warnings;

use File::Path qw(make_path);

sub get_config {
    my %config = (
        name    => 'WHMCS-DNS',
        options => [
            { name => 'host', type => 'text', locale_text => 'Node name (use whmcs-dns-bridge)' },
            { name => 'user', type => 'text', locale_text => 'Local user (use root)' },
            { name => 'pass', type => 'text', locale_text => 'Local marker (use local-socket)' },
        ],
    );
    return wantarray ? %config : \%config;
}

sub setup {
    my ( undef, %opts ) = @_;
    my $remote_user = $ENV{'REMOTE_USER'} || '';
    return ( 0, 'Invalid WHM user.' ) if $remote_user !~ /\A[a-zA-Z0-9_]+\z/;

    my $user = $opts{'user'} || 'root';
    my $host = $opts{'host'} || 'whmcs-dns-bridge';
    my $pass = $opts{'pass'} || 'local-socket';
    return ( 0, 'Invalid local user.' ) if $user !~ /\A[a-zA-Z0-9_]+\z/;
    return ( 0, 'Invalid node name.' ) if $host !~ /\A[a-zA-Z0-9_.-]+\z/;
    return ( 0, 'Invalid local marker.' ) if $pass =~ /[\r\n\0]/;

    my $directory = "/var/cpanel/cluster/$remote_user/config";
    make_path( $directory, { mode => 0700 } );
    my $path = "$directory/$host";
    open my $file, '>', $path or return ( 0, "Could not write $path: $!" );
    chmod 0600, $path or return ( 0, "Could not secure $path: $!" );
    print {$file} "#version 2.0\nuser=$user\nhost=$host\npass=$pass\nmodule=WHMCSDNS\ndebug=off\n";
    close $file or return ( 0, "Could not close $path: $!" );

    return ( 1, 'WHMCS-DNS local bridge configured.', '', $host );
}

1;

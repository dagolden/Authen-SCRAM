use 5.008;
use strict;
use warnings;

package Authen::SCRAM;
# ABSTRACT: Salted Challenge Response Authentication Mechanism (RFC 5802)

our $VERSION = '0.005';

1;

=for Pod::Coverage BUILD

=head1 SYNOPSIS

    use Authen::SCRAM::Client;
    use Authen::SCRAM::Server;
    use Try::Tiny;

    ### CLIENT SIDE ###

    $client = Authen::SCRAM::Client->new(
        username => 'johndoe',
        password => 'trustno1',
    );

    try {
        $client_first = $client->first_msg();

        # send to server and get server-first-message

        $client_final = $client->final_msg( $server_first );

        # send to server and get server-final-message

        $client->validate( $server_final );
    }
    catch {
        die "Authentication failed!"
    };

    ### SERVER SIDE ###

    $server = Authen::SCRAM::Server->new(
        credential_cb => \&get_credentials,
    );

    $username = try {
        # get client-first-message

        $server_first = $server->first_msg( $client_first );

        # send to client and get client-final-message

        $server_final = $server->final_msg( $client_final );

        # send to client

        return $server->authorization_id; # returns valid username
    }
    catch {
        die "Authentication failed!"
    };

=head1 DESCRIPTION

The modules in this distribution implement the Salted Challenge Response
Authentication Mechanism (SCRAM) from RFC 5802.

See L<Authen::SCRAM::Client> and L<Authen::SCRAM::Server> for usage details.

=cut

# vim: ts=4 sts=4 sw=4 et:

use 5.008;
use strict;
use warnings;

package Authen::SCRAM::Client;
# ABSTRACT: RFC 5802 SCRAM client

our $VERSION = '0.001';

use Moo;

use Authen::SASL::SASLprep qw/saslprep/;
use MIME::Base64 qw/encode_base64/;
use PBKDF2::Tiny 0.003 qw/derive digest_fcn hmac/;
use Types::Standard qw/Str Num/;

use namespace::clean;

#--------------------------------------------------------------------------#
# public attributes
#--------------------------------------------------------------------------#

=attr username (required)

Authentication username

=cut

has username => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

=attr password (required)

Authentication password

=cut

has password => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

#--------------------------------------------------------------------------#
# provided by Authen::SCRAM::Role::Common
#--------------------------------------------------------------------------#

with 'Authen::SCRAM::Role::Common';

=attr digest

Name of a digest function available via L<PBKDF2::Tiny>.  Valid values are
SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512.  Defaults to SHA-1.

=cut

=attr nonce_size

Size of the client-generated nonce, in bits.  Defaults to 192.
The server-nonce will be appended, so the final nonce size will
be substantially larger.

=cut

#--------------------------------------------------------------------------#
# private attributes
#--------------------------------------------------------------------------#

has _prepped_user => (
    is  => 'lazy',
    isa => Str,
);

sub _build__prepped_user {
    my ($self) = @_;
    return saslprep( $self->username );
}

has _prepped_pass => (
    is  => 'lazy',
    isa => Str,
);

sub _build__prepped_pass {
    my ($self) = @_;
    return saslprep( $self->password );
}

#--------------------------------------------------------------------------#
# public methods
#--------------------------------------------------------------------------#

=method first_msg

    $client_first_msg = $client->first_msg();

This takes no arguments and returns the C<client-first-message> string to be
sent to the server to initiate a SCRAM session.  Calling this again will reset
the internal state and initiate a new session.  This will throw an exception
should an error occur.

=cut

sub first_msg {
    my ($self) = @_;

    my ( $user, $pass ) = ( $self->_prepped_user, $self->_nonce );
    for my $str ( $user, $pass ) {
        $str =~ s/=/=3d/g;
        $str =~ s/,/=2c/g;
    }
    return sprintf( "n,,n=%s,r=%s", $user, $pass );
}

=method final_msg

    $client_final_msg = $client->final_msg( $server_first_msg );

This takes the C<server-first-message> received from the server and returns the
C<client-final-message> string containing the authentication proof to be sent
to the server.  This will throw an exception should an error occur.

=cut

sub final_msg {
    my ( $self, $msg ) = @_;
}

=method validate

    $client->validate( $server_final_msg );

This takes the C<server-final-message> received from the server and verifies
that the server actually has a copy of the client credentials.  It will return
true if valid and throw an exception, otherwise.

=cut

sub validate {
    my ( $self, $msg ) = @_;

    return 1;
}

1;

=for Pod::Coverage BUILD

=head1 SYNOPSIS

    use Authen::SCRAM;


=head1 DESCRIPTION

This module implements the client-side SCRAM algorithm.

=cut

# vim: ts=4 sts=4 sw=4 et:

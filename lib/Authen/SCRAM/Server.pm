use 5.008;
use strict;
use warnings;

package Authen::SCRAM::Server;
# ABSTRACT: RFC 5802 SCRAM Server

our $VERSION = '0.001';

use Moo;

use Authen::SASL::SASLprep qw/saslprep/;
use Crypt::URandom qw/urandom/;
use MIME::Base64 qw/encode_base64/;
use PBKDF2::Tiny 0.003 qw/derive digest_fcn hmac/;
use Types::Standard qw/Str Num/;

use namespace::clean;

with 'Authen::SCRAM::Role::Common';

#--------------------------------------------------------------------------#
# public attributes
#--------------------------------------------------------------------------#

=method credential_cb (required)

This attribute must contain a code reference that takes a username and
returns the four user-credential parameters required by SCRAM: C<salt>, C<StoredKey>,
C<ServerKey>, and C<iteration count>.

    ($salt, $stored_key, $server_key, $iterations) =
        $server->credential_cb->( $username );

See L<RFC 5802: SCRAM Algorithm Overview|http://tools.ietf.org/html/rfc5802#section-3>
for details.

=cut

has credential_cb => (
    is => 'ro',
    isa => CodeRef,
    required => 1,
);

=method auth_proxy_cb

If provided, this attribute must contain a code reference that takes an
B<authentication> username and a B<authorization> username, and return
a true value if the authentication username is permitted to act as
the authorization username:

    $bool = $server->auth_proxy_cb->(
        $authentication_user, $authorization_user
    );

It will only be all called if the authentication username has successfully
authenticated.  Both usernames are expected to be prepared via C<SASLprep> with
any transport encoding removed.

=cut

has auth_proxy_cb => (
    is => 'ro',
    isa => CodeRef,
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
# public methods
#--------------------------------------------------------------------------#

=method first_msg

    $server_first_msg = $server->first_msg( $client_first_msg );

This takes the C<client-first-message> received from the client and returns the
C<server-first-message> string to be sent to the client to continue a SCRAM
session.  Calling this again will reset the internal state and initiate a new
session.  This will throw an exception should an error occur.

=cut

sub first_msg {
    my ($self, $msg) = @_;
}

=method final_msg

    $server_final_msg = $server->final_msg( $client_final_msg );

This takes the C<client-final-message> received from the client and returns the
C<server-final-message> string containing the verification signature to be sent
to the client.  This will throw an exception should an error occur.

=cut

sub final_msg {
    my ( $self, $msg ) = @_;
}

=method validate

    $client->validate();

This takes no arguments and verifies that the client credentials match the
server credentials.  It will return true if valid and throw an exception,
otherwise.

=cut

sub validate {
    my ( $self ) = @_;

    return 1;
}

1;

=for Pod::Coverage BUILD

=head1 SYNOPSIS

    use Authen::SCRAM::Server;

=head1 DESCRIPTION

This module might be cool, but you'd never know it from the lack
of documentation.

=head1 USAGE

Good luck!

=head1 SEE ALSO

=for :list
* Maybe other modules do related things.

=cut

# vim: ts=4 sts=4 sw=4 et:

use 5.008;
use strict;
use warnings;

package Authen::SCRAM::Role::Common;
# ABSTRACT: Common SCRAM algorithms

our $VERSION = '0.001';

use Moo::Role;

use Crypt::URandom qw/urandom/;
use MIME::Base64 qw/encode_base64/;
use PBKDF2::Tiny 0.003 qw/digest_fcn hmac/;
use Types::Standard -all;

use namespace::clean;

has digest => (
    is      => 'ro',
    isa     => Enum [qw/SHA-1 SHA-224 SHA-256 SHA-384 SHA-512/],
    default => 'SHA-1',
);

has nonce_size => (
    is      => 'ro',
    isa     => Num,
    default => 192,
);

has _nonce => (
    is      => 'lazy',
    isa     => Str,
    clearer => 1,
);

sub _build__nonce {
    my ($self) = @_;
    return encode_base64( urandom( $self->nonce_size / 8 ) );
}

1;

=for Pod::Coverage BUILD

=head1 SYNOPSIS

    use Authen::SCRAM::Role::Common;

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

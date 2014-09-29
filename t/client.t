use 5.008001;
use strict;
use warnings;
use Test::More 0.96;
use Test::FailWarnings;
use Test::Fatal;
binmode( Test::More->builder->$_, ":utf8" )
  for qw/output failure_output todo_output/;

my $CLASS = "Authen::SCRAM::Client";
require_ok($CLASS);

sub _get_client {
    return $CLASS->new( username => 'user', password => 'pencil', @_ );
}

subtest "constructors" => sub {
    my $client = _get_client;
    is( $client->digest,     'SHA-1',  "default digest" );
    is( $client->username,   'user',   "username attribute" );
    is( $client->password,   'pencil', "password attribute" );
    is( $client->nonce_size, 192,      "nonce size attribute" );

    for my $d (qw/1 224 256 384 512/) {
        my $obj =
          new_ok( $CLASS, [ username => 'user', password => 'pencil', digest => "SHA-$d" ] );
        is( $obj->digest, "SHA-$d", "digest set correctly to SHA-$d" );
    }

    like(
        exception { _get_client( digest => 'MD5' ) },
        qr/did not pass type constraint/,
        "bad digest type throws exception"
    );

};

done_testing;
# COPYRIGHT

# vim: ts=4 sts=4 sw=4 et:

#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2018, cPanel, L.L.C.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../pkg";

use Cpanel::Version ();
use Test::Assessor  ();
use Test::More;
use Test::MockModule;

use Cpanel::Security::Advisor::Assessors::Imunify360 ();

plan skip_all => 'Requires cPanel & WHM v80 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.79' );

plan tests => 4;

my $mocked_version_module    = Test::MockModule->new('Cpanel::Version');
my $mocked_imunify360_module = Test::MockModule->new('Whostmgr::Imunify360');

subtest 'Requires cPanel v80 or later' => sub {
    plan tests => 1;

    $mocked_version_module->mock( getversionnumber => sub { '11.70' } );

    my $advice = get_advice();

    is_deeply( $advice, [], "Should not get advice for versions lower than 80" ) or diag explain $advice;
};

$mocked_version_module->mock( getversionnumber => sub { '11.80' } );

subtest 'Advice to buy an Imunify360 license' => sub {
    plan tests => 1;

    $mocked_imunify360_module->mock( is_imunify360_licensed => sub { 0 } );

    my $advice      = get_advice();
    my $advice_text = $advice->[0]->{'advice'}->{'text'};

    is( $advice_text, "Use Imunify360 to protect your server against attacks.", "It should advice buying an Imunify360 license" );
};

subtest 'Has a license but Imunify360 is not installed' => sub {
    plan tests => 1;

    $mocked_imunify360_module->mock( is_imunify360_licensed  => sub { 1 } );
    $mocked_imunify360_module->mock( is_imunify360_installed => sub { 0 } );

    my $advice      = get_advice();
    my $advice_text = $advice->[0]->{'advice'}->{'text'};

    is( $advice_text, "You have an Imunify360 license, but you do not have Imunify360 installed on your server.", "It should advice installing Imunify360" );
};

subtest 'Imunify360 is installed' => sub {
    plan tests => 1;

    $mocked_imunify360_module->mock( is_imunify360_licensed  => sub { 1 } );
    $mocked_imunify360_module->mock( is_imunify360_installed => sub { 1 } );

    my $advice      = get_advice();
    my $advice_text = $advice->[0]->{'advice'}->{'text'};

    is( $advice_text, "Your server is protected by Imunify360.", "It should say that the server is protected" );
};

sub get_advice {
    my $object = Test::Assessor->new( assessor => 'Imunify360' );
    $object->generate_advice();
    my $advice = $object->get_advice();
    $object->clear_advice();

    return $advice;
}

package Cpanel::Security::Advisor::Assessors::Imunify360;

# Copyright (c) 2019, cPanel, L.L.C.
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
use base 'Cpanel::Security::Advisor::Assessors';

use Cpanel::Config::Sources ();
use Cpanel::Version         ();
use Whostmgr::Imunify360    ();

use Cpanel::Imports;

our $IMUNIFY360_MINIMUM_CPWHM_VERSION = '11.79';    # we want it usable on both development and release builds for 11.80

sub version {
    return '1.00';
}

sub generate_advice {
    my ($self) = @_;

    eval {
        if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', $IMUNIFY360_MINIMUM_CPWHM_VERSION ) ) {

            $self->_suggest_imunify360;
        }
    };
    if ( my $exception = $@ ) {
        print STDERR $exception;    # STDERR gets sent to ULC/logs/error_log.
        die $exception;
    }

    return 1;
}

sub _suggest_imunify360 {
    my ($self) = @_;

    if ( !Whostmgr::Imunify360::is_imunify360_licensed() ) {
        my $imunify360_price = Whostmgr::Imunify360::get_imunify360_price();
        my $store_url        = Cpanel::Config::Sources::get_source('STORE_SERVER_URL');
        my $url              = "$store_url/view/imunify360/license-options";

        my $purchase_link =
          $imunify360_price
          ? locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3] for [_4].', $url, 'target', '_blank', "\$$imunify360_price/month" )
          : locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3].',          $url, 'target', '_blank' );

        $self->add_warn_advice(
            key          => 'Imunify360_purchase',
            text         => locale()->maketext('Use [asis,Imunify360] to protect your server.'),
            suggestion   => locale()->maketext('[asis,Imunify360] blocks attacks in real-time using a combination of technologies, including Advanced Firewall, Intrusion Detection and Protection System, Malware Detection, [asis,Proactive Defense™], Patch Management, and Reputation Management.') . '<br /><br />' . $purchase_link,
            block_notify => 1,                                                                                                                                                                                                                                                       # Do not send a notification about this
        );
    }
    elsif ( !Whostmgr::Imunify360::is_imunify360_installed() ) {

        $self->add_warn_advice(
            key          => 'Imunify360_install',
            text         => locale()->maketext('You have an [asis,Imunify360] license, but you do not have [asis,Imunify360] installed on your server.'),
            suggestion   => locale()->maketext('Install [asis,Imunify360].'),
            block_notify => 1,                                                                                                                                                                                                                                                       # Do not send a notification about this
        );
    }
    else {
        $self->add_good_advice(
            key          => 'Imunify360_present',
            text         => locale()->maketext('Your server is protected by [asis,Imunify360].'),
            block_notify => 1,                                                                                                                                                                                                                                                       # Do not send a notification about this
        );
    }

    return 1;
}

1;

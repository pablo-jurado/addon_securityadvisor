package Cpanel::Security::Advisor::Assessors::Imunify360;

# Copyright 2019, cPanel, L.L.C.
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
# DISCLAIMED. IN NO EVENT SHALL cPanel, L.L.C BE LIABLE FOR ANY
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
use Cpanel::HTTP::Client    ();
use Cpanel::JSON            ();
use Cpanel::Sys::OS::Check  ();
use Cpanel::Sys::GetOS      ();
use Whostmgr::Imunify360    ();

use Cpanel::Imports;

our $IMUNIFY360_MINIMUM_CPWHM_VERSION = '11.79';    # we want it usable on both development and release builds for 11.80

=head2 version()

Return the Assessor Version

=cut

sub version {
    return '1.00';
}

=head2 generate_advice()

Returns the proper advice if the following conditions are met.
Checks the OS because Imunify360 is only available in CentOS6, CentOS7, and CloudLinux.
Checks if Imunify360 is enabled in Manage2.
Also checks if the cPanel version is 80 or later.

There are four different types of advice:
    - Imunify360 is installed and has a current license ( key  => 'Imunify360_present' ).
    - Imunify360 is installed and needs a new license ( key => 'Imunify360_update_license' ).
    - Imunify360 is uninstalled and has a current license ( key => 'Imunify360_install' ).
    - Imunify360 is uninstalled and needs a new license. ( key => 'Imunify360_purchase' ).

=cut

sub generate_advice {
    my ($self) = @_;
    my $is_imunify360_disabled = Whostmgr::Imunify360::get_imunify360_data()->{'disabled'};

    eval {
        if (   Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', $IMUNIFY360_MINIMUM_CPWHM_VERSION )
            && _is_imunify360_supported()
            && !$is_imunify360_disabled ) {
            $self->_suggest_imunify360;
        }
    };
    if ( my $exception = $@ ) {
        print STDERR $exception;    # STDERR gets sent to ULC/logs/error_log.
        die $exception;
    }

    return 1;
}

sub _get_purchase_and_install_template {
    return << 'TEMPLATE';
[%- locale.maketext('[asis,Imunify360] delivers sophisticated detection and display of security threats, powered by a self-learning firewall with herd immunity. It blocks attacks in real-time using a combination of technologies, including:') %]
    <ul>
        <li>[%- locale.maketext('[asis,Proactive Defense™]') -%]</li>
        <li>[%- locale.maketext('Smart Intrusion Detection and Protection System')-%]</li>
        <li>[%- locale.maketext('Malware Detection')-%]</li>
        [% IF data.include_kernelcare %]
        <li>[%- locale.maketext('Patch Management via [asis,KernelCare]')-%]</li>
        [% END %]
        <li><a href="https://go.cpanel.net/buyimunify360" target="_new">[%- locale.maketext('Learn more about [asis,Imunify360]')%]</a></li>
    </ul>
[%
IF data.price;
    locale.maketext( '[output,url,_1,Get Imunify360,_2,_3] for $[_4]/month.', data.path, 'target', '_parent', data.price );
ELSE;
    locale.maketext( '[output,url,_1,Get Imunify360,_2,_3].', data.path, 'target', '_parent');
END;
%]
TEMPLATE
}

sub _get_purchase_template {
    return << 'TEMPLATE';
<style>
#Imunify360_update_license blockquote {
    margin:0
}
</style>
<ul>
    <li>
    [%-
    locale.maketext(
        'To purchase a license, visit the [output,url,_1,cPanel Store,_2,_3].',
        data.path,
        'target',
        '_parent',
    )
    -%]
    </li>
    <li>
    [%- locale.maketext(
        'To uninstall [asis,Imunify360], read the [output,url,_1,Imunify360 Documentation,_2,_3].',
        'https://docs.imunify360.com/uninstall/',
        'target',
        '_blank',
    ) -%]
    </li>
</ul>
TEMPLATE
}

sub _get_install_template {
    return << 'TEMPLATE';
[%- locale.maketext(
        '[output,url,_1,Install Imunify360,_2,_3].',
        data.path,
        'target',
        '_parent'
) -%]
TEMPLATE
}

sub _process_template {
    my ( $template_ref, $args )   = @_;
    my ( $ok,           $output ) = Cpanel::Template::process_template(
        'whostmgr',
        {
            'template_file' => $template_ref,
            'data'          => $args,
        }
    );
    return $output if $ok;
    die "Template processing failed: $output";
}

sub _suggest_imunify360 {
    my ($self) = @_;

    if (  !Whostmgr::Imunify360::is_imunify360_licensed()
        && Whostmgr::Imunify360::is_imunify360_installed() ) {
        my $output = _process_template(
            \_get_purchase_template(),
            {
                'path' => $self->base_path('scripts12/purchase_imunify360_init'),
            },
        );

        $self->add_warn_advice(
            key          => 'Imunify360_update_license',
            text         => locale()->maketext('[asis,Imunify360] is installed but you do not have a current license.'),
            suggestion   => $$output,
            block_notify => 1,                                                                                             # Do not send a notification about this
        );
    }
    elsif (!Whostmgr::Imunify360::is_imunify360_licensed()
        && !Whostmgr::Imunify360::is_imunify360_installed() ) {

        my $imunify360_price = Whostmgr::Imunify360::get_imunify360_price();

        my $output = _process_template(
            \_get_purchase_and_install_template(),
            {
                'path'               => $self->base_path('scripts12/purchase_imunify360_init'),
                'price'              => $imunify360_price,
                'include_kernelcare' => Whostmgr::Imunify360::is_centos_6_or_7()
                  && !Whostmgr::Imunify360::get_kernelcare_data()->{'disabled'},
            },
        );

        $self->add_warn_advice(
            key          => 'Imunify360_purchase',
            text         => locale()->maketext('Use [asis,Imunify360] for complete protection against attacks on your servers.'),
            suggestion   => $$output,
            block_notify => 1,                                                                                                      # Do not send a notification about this
        );
    }
    elsif ( !Whostmgr::Imunify360::is_imunify360_installed() ) {
        my $output = _process_template(
            \_get_install_template(),
            {
                'path'               => $self->base_path('scripts12/install_imunify360'),
                'include_kernelcare' => Whostmgr::Imunify360::is_centos_6_or_7()
                  && !Whostmgr::Imunify360::get_kernelcare_data()->{'disabled'},
            }
        );

        $self->add_warn_advice(
            key          => 'Imunify360_install',
            text         => locale()->maketext('You have an [asis,Imunify360] license, but you do not have [asis,Imunify360] installed on your server.'),
            suggestion   => $$output,
            block_notify => 1,                                                                                                                              # Do not send a notification about this
        );
    }
    else {
        my $imunify_whm_link = locale()->maketext(
            '[output,url,_1,Open Imunify360,_2,_3].',
            $self->base_path('cgi/imunify/handlers/index.cgi#/admin/dashboard/incidents'),
            'target' => '_parent'
        );

        $self->add_good_advice(
            key  => 'Imunify360_present',
            text => locale()->maketext(
                q{Your server is protected by [asis,Imunify360]. For help getting started, read [output,url,_1,Imunify360’s documentation,_2,_3].},
                'https://www.imunify360.com/getting-started',
                'target' => '_blank',
            ),
            suggestion   => $imunify_whm_link,
            block_notify => 1,                   # Do not send a notification about this
        );
    }

    return 1;
}

sub _is_imunify360_supported {
    my $centos_version = Cpanel::Sys::OS::Check::get_strict_centos_version();
    my $os             = Cpanel::Sys::GetOS::getos();
    my $os_ok          = ( ( $os =~ /^centos$/ && ( $centos_version == 6 || $centos_version == 7 ) ) || $os =~ /^cloudlinux$/i );
    return $os_ok;
}

1;

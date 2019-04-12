package Cpanel::Security::Advisor::Assessors::SSH;

# Copyright (c) 2013, cPanel, Inc.
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
# DISCLAIMED. IN NO EVENT SHALL cPanel, L.L.C. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Whostmgr::Services::SSH::Config ();

use base 'Cpanel::Security::Advisor::Assessors';

sub version {
    return '1.01';
}

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_ssh_settings;
    $self->_check_for_ssh_version;

    return 1;
}

sub _check_for_ssh_settings {
    my ($self) = @_;

    my $scfg = Whostmgr::Services::SSH::Config->new();
    my $sshd_config = $scfg->get_config();
    if ( $scfg->get_config('PasswordAuthentication') =~ m/yes/i || $scfg->get_config('ChallengeResponseAuthentication') =~ m/yes/i ) {
        $self->add_bad_advice(
            'key'        => 'SSH_password_authentication_enabled',
            'text'       => $self->_lh->maketext('SSH password authentication is enabled.'),
            'suggestion' => $self->_lh->maketext(
                'Disable SSH password authentication in the “[output,url,_1,SSH Password Authorization Tweak,_2,_3]” area',
                $self->base_path('scripts2/tweaksshauth'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'SSH_password_authentication_disabled',
            'text' => $self->_lh->maketext('SSH password authentication is disabled.'),
        );

    }

    if ( $scfg->get_config('PermitRootLogin') =~ m/yes/i || !$scfg->('PermitRootLogin') ) {
        $self->add_bad_advice(
            'key'        => 'SSH_direct_root_login_permitted',
            'text'       => $self->_lh->maketext('SSH direct root logins are permitted.'),
            'suggestion' => $self->_lh->maketext(
                'Manually edit /etc/ssh/sshd_config and change PermitRootLogin to “without-password” or “no”, then restart SSH in the “[output,url,_1,Restart SSH,_2,_3]” area',
                $self->base_path('scripts/ressshd'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'SSH_direct_root_logins_disabled',
            'text' => $self->_lh->maketext('SSH direct root logins are disabled.'),
        );

    }

    return 1;

}

sub _check_for_ssh_version {
    my ($self) = @_;

    my $installed_rpms = $self->get_installed_rpms();
    my $available_rpms = $self->get_available_rpms();

    my $current_sshversion = $installed_rpms->{'openssh-server'};
    my $latest_sshversion  = $available_rpms->{'openssh-server'};

    if ( length $current_sshversion && length $latest_sshversion ) {
        if ( $current_sshversion lt $latest_sshversion ) {
            $self->add_bad_advice(
                'key'        => 'SSH_version_outdated',
                'text'       => $self->_lh->maketext('Current SSH version is out of date.'),
                'suggestion' => $self->_lh->maketext(
                    'Update current system software in the “[output,url,_1,Update System Software,_2,_3]” area',
                    $self->base_path('scripts/dialog?dialog=updatesyssoftware'),
                    'target',
                    '_blank'
                ),
            );
        }
        else {
            $self->add_good_advice(
                'key'  => 'SSH_is_current',
                'text' => $self->_lh->maketext( 'Current SSH version is up to date: [_1]', $current_sshversion )
            );
        }
    }
    else {
        $self->add_warn_advice(
            'key'        => 'SSH_can_not_determine_version',
            'text'       => $self->_lh->maketext('Unable to determine SSH version'),
            'suggestion' => $self->_lh->maketext('Ensure that yum and rpm are working on your system.')
        );
    }

    return 1;

}

1;

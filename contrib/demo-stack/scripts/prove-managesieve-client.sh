#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

perl <<'PERL'
use strict;
use warnings;

BEGIN {
    for my $module (qw(Net::ManageSieve IO::Socket::SSL)) {
        eval "require $module; 1"
          or die "proof failed: missing Perl module $module (install with: cpan -T Net::ManageSieve IO::Socket::SSL)\n";
    }
    IO::Socket::SSL->import(qw(SSL_VERIFY_NONE));
}

use Time::HiRes qw(time);

sub env_value {
    my ($name, $default) = @_;
    return $ENV{$name} if exists $ENV{$name} && length $ENV{$name};
    return $default;
}

sub positive_int_env {
    my ($name, $default) = @_;
    my $value = env_value($name, $default);
    die "$name must be an integer\n" unless $value =~ /\A[1-9][0-9]*\z/;
    return int($value);
}

sub safe_error {
    my ($client) = @_;
    my $error = defined $client ? ($client->error || $@ || "unknown error") : ($@ || "unknown error");
    chomp $error;
    $error =~ s/Authenticate\s+"[^"]+"\s+"[^"]+"/Authenticate "<redacted>" "<redacted>"/gi;
    $error =~ s/([Pp]ass(?:word)?\s*[:=]\s*)\S+/${1}<redacted>/g;
    return $error || "unknown error";
}

sub capability_value {
    my ($capabilities, $name) = @_;
    return undef unless defined $capabilities && ref($capabilities) eq "HASH";
    return $capabilities->{lc($name)};
}

sub require_capability {
    my ($capabilities, $name, $label) = @_;
    return if exists $capabilities->{lc($name)};
    my $keys = join(", ", sort keys %{$capabilities});
    die "$label did not advertise $name; keys=[$keys]\n";
}

sub reject_capability {
    my ($capabilities, $name, $label) = @_;
    return unless exists $capabilities->{lc($name)};
    die "$label unexpectedly advertised $name\n";
}

sub require_sieve_extensions {
    my ($capabilities, $label, @required) = @_;
    my $sieve = capability_value($capabilities, "sieve");
    die "$label did not advertise SIEVE\n" unless defined $sieve;

    my %advertised = map { lc($_) => 1 } grep { length $_ } split /[\s,]+/, $sieve;
    my @missing = grep { !$advertised{lc($_)} } @required;
    die "$label SIEVE extensions missing: @missing; sieve=$sieve\n" if @missing;
}

sub script_present {
    my ($scripts, $name) = @_;
    return scalar grep { defined $_ && $_ eq $name } @{$scripts};
}

my $host = env_value("DEMO_SIEVE_HOST", "127.0.0.1");
my $port = positive_int_env("DEMO_SIEVE_PORT", 4190);
my $timeout = positive_int_env("DEMO_WAIT_SECONDS", 20);
my $user = env_value("DEMO_USER", "alice\@example.test");
my $password = env_value("DEMO_PASSWORD", "demo-secret");
my $script_name = "demo-net-managesieve-" . int(time()) . "-$$";
my $script_body = "require [\"fileinto\", \"date\", \"vacation\"];\nkeep;\n";

my $client;
my $created = 0;
my $failure;

eval {
    $client = Net::ManageSieve->new(
        $host,
        Port => $port,
        Timeout => $timeout,
        tls => {
            mode => "require",
            SSL_verify_mode => SSL_VERIFY_NONE,
            SSL_verifycn_scheme => "none",
        },
    ) or die "connect or STARTTLS failed: " . safe_error(undef) . "\n";

    my $pre_auth = $client->capabilities;
    require_capability($pre_auth, "sasl", "post-STARTTLS pre-auth capability");
    reject_capability($pre_auth, "starttls", "post-STARTTLS pre-auth capability");
    require_sieve_extensions(
        $pre_auth,
        "post-STARTTLS pre-auth capability",
        qw(date vacation vacation-seconds),
    );

    $client->login($user, $password)
      or die "login failed: " . safe_error($client) . "\n";

    my $post_auth = $client->capabilities(1)
      or die "post-auth CAPABILITY failed: " . safe_error($client) . "\n";
    require_sieve_extensions($post_auth, "post-auth backend capability", qw(date vacation));

    my $scripts_before = $client->listscripts
      or die "LISTSCRIPTS before PUTSCRIPT failed: " . safe_error($client) . "\n";

    $client->putscript($script_name, $script_body)
      or die "PUTSCRIPT failed: " . safe_error($client) . "\n";
    $created = 1;

    my $fetched = $client->getscript($script_name);
    die "GETSCRIPT failed: " . safe_error($client) . "\n" unless defined $fetched;
    die "GETSCRIPT did not return the uploaded script body\n" unless $fetched eq $script_body;

    $client->deletescript($script_name)
      or die "DELETESCRIPT failed: " . safe_error($client) . "\n";
    $created = 0;

    my $scripts_after = $client->listscripts
      or die "LISTSCRIPTS after DELETESCRIPT failed: " . safe_error($client) . "\n";
    die "temporary script still listed after DELETESCRIPT\n" if script_present($scripts_after, $script_name);

    my $before_count = scalar(@{$scripts_before});
    $before_count-- if $before_count > 0;
    my $cipher = $client->get_cipher || "unknown";
    my $pre_sieve = capability_value($pre_auth, "sieve") || "";
    my $post_sieve = capability_value($post_auth, "sieve") || "";
    my $post_has_vacation_seconds = ($post_sieve =~ /(?:^|\s)vacation-seconds(?:\s|$)/i) ? "yes" : "no";

    print "client=Net::ManageSieve version=$Net::ManageSieve::VERSION\n";
    print "tls_cipher=$cipher\n";
    print "pre_auth_sieve=$pre_sieve\n";
    print "post_auth_sieve=$post_sieve\n";
    print "post_auth_has_date=yes\n";
    print "post_auth_has_vacation=yes\n";
    print "post_auth_has_vacation-seconds=$post_has_vacation_seconds\n";
    print "listscripts_before_count=$before_count\n";
    print "getscript_matches=yes\n";
    print "temporary_script_removed=yes\n";
    1;
} or do {
    $failure = $@ || "unknown proof failure\n";
};

my $cleanup_failure;
if (defined $client && $created) {
    $client->deletescript($script_name)
      or $cleanup_failure = "cleanup DELETESCRIPT failed: " . safe_error($client);
}

if (defined $client) {
    eval { $client->logout; 1 } or do {
        $cleanup_failure ||= "LOGOUT failed: " . safe_error($client);
    };
}

if ($failure) {
    chomp $failure;
    print STDERR "proof failed: $failure";
    print STDERR "; $cleanup_failure" if $cleanup_failure;
    print STDERR "\n";
    exit 1;
}

if ($cleanup_failure) {
    print STDERR "proof failed: $cleanup_failure\n";
    exit 1;
}

print "proof ok: external ManageSieve STARTTLS client saw date/vacation and completed PUT/GET/DELETE through the public demo-stack socket\n";
PERL

package Net::OAuth::Client;
use warnings;
use strict;
use base qw(Class::Accessor::Fast);
__PACKAGE__->mk_accessors(qw/id secret callback is_v1a user_agent site debug/);
use LWP::UserAgent;
use URI;
use Net::OAuth;
use Net::OAuth::Message;
use Carp;

sub new {
  my $class = shift;
  my $client_id = shift;
  my $client_secret = shift;
  my %opts = @_;
  $opts{user_agent} ||= LWP::UserAgent->new;
  $opts{id} = $client_id;
  $opts{secret} = $client_secret;
  $opts{is_v1a} = defined $opts{callback};
  my $self = bless \%opts, $class;
  return $self;
}

sub request {
  my $self = shift;
  my $response = $self->user_agent->request(@_);
}

sub _parse_oauth_response {
  my $self = shift;
  my $do_what = shift;
  my $http_res = shift;
  my $msg = "Unable to $do_what: Request for " . $http_res->request->uri . " failed";
  unless ($http_res->is_success) {
    if ($self->debug) { 
      $msg .= "," . $http_res->as_string . " ";      
    }
    elsif (
      $http_res->content_type eq 'application/x-www-form-urlencoded'
      and $http_res->decoded_content =~ /\boauth_problem=(\w+)/
      ) { 
      $msg .= ", reason: " . $1;      
    }
    else {
      $msg .= ": " . $http_res->status_line . " (pass debug=>1 to Net::OAuth::Client->new to dump the entire response)";
    }
    croak $msg;
  }
  my $oauth_res = _parse_url_encoding($http_res->decoded_content);
  foreach my $k (qw/token token_secret/) {
    croak "Unable to $do_what: server response is missing '$k'" unless defined $oauth_res->{$k};
  }
  return $oauth_res;
  
}

sub _parse_url_encoding {
  my $str = shift;
  my @pairs = split '&', $str;
  my %params;
	foreach my $pair (@pairs) {
        my ($k,$v) = split /=/, $pair;
        if (defined $k and defined $v) {
            $v =~ s/(^"|"$)//g;
            ($k,$v) = map Net::OAuth::Message::decode($_), $k, $v;
            $k =~ s/^oauth_//;
            $params{$k} = $v;
        }
    }
	return \%params;
}

sub get_request_token {
  my $self = shift;
  my %params = @_;
  my $oauth_req = $self->_make_request(
    "request token", 
    request_method => $self->request_token_method,
    request_uri => $self->_make_url("request_token"),
    %params
  );
  $oauth_req->sign;
  my $http_res = $self->request(HTTP::Request->new(
    $self->request_token_method => $oauth_req->to_url
  ));
  my $oauth_res = $self->_parse_oauth_response('get a request token', $http_res);
  $self->is_v1a(0) unless defined $oauth_res->{callback_confirmed};
  return $oauth_res;
}

sub authorize_url {
  my $self = shift;
  my %params = @_;
  # allow user to get request token their own way
  unless (defined $params{token} and defined $params{token_secret}) {
    my $request_token = $self->get_request_token;
    $params{token} = $request_token->token;
    $params{token_secret} = $request_token->token_secret;
  }
  my $oauth_req = $self->_make_request(
    'user auth',
    request_uri => $self->_make_url('authorize'),
    %params
  );
  return $oauth_req->to_url;
}

sub get_access_token {
  my $self = shift;
  my $code = shift;
  my %params = @_;
  
  my $oauth_req = $self->_make_request(
    'access token', 
    request_method => $self->access_token_method,
    request_uri => $self->_make_url('access_token'),
    verifier => $code,
    %params
  );
  $oauth_req->sign;
  
  my $http_res = $self->request(HTTP::Request->new(
    $self->access_token_method => $oauth_req->to_url
  ));

  my $oauth_res = $self->_parse_oauth_response('get an access token', $http_res);
  
  return Net::OAuth2::AccessToken->new(%$oauth_res);
}

sub access_token_url {
  return shift->_make_url('access_token', @_);
}

sub request_token_url {
  return shift->_make_url('request_token', @_);
}

sub access_token_method {
  return shift->{access_token_method} || 'GET';
}

sub request_token_method {
  return shift->{request_token_method} || 'GET';
}

sub _make_request {
  my $self = shift;
  my $type = shift;
  my %params = @_;
  my %defaults = (
    nonce => int( rand( 2**32 ) ),
    timestamp => time,
    consumer_key => $self->key,
    consumer_secret => $self->secret,
    callback => $self->callback,
    signature_method => 'HMAC-SHA1',
    request_method => 'GET',
  );
  $defaults{protocol_version} = Net::OAuth::PROTOCOL_VERSION_1_0A if $self->is_v1a;
  my $req = Net::OAuth->request($type)->new(
    %defaults,
    %params
  );
  return $req;
}

sub _make_url {
  my $self = shift;
  my $thing = shift;
  my $path = $self->{"${thing}_url"} || $self->{"${thing}_path"} || "/oauth/${thing}";
  return $self->site_url($path, @_);
}

sub site_url {
  my $self = shift;
  my $path = shift;
  my %params = @_;
  my $url;
  if (defined $self->{site}) {
    $url = URI->new_abs($path, $self->{site});
  }
  else {
    $url = URI->new($path);
  }
  if (@_) {
    $url->query_form($url->query_form , %params);
  }
  return $url;
}

=head1 NAME

Net::OAuth::Client - OAuth 1.0A Client

=head1 SEE ALSO

L<Net::OAuth>

=head1 LICENSE AND COPYRIGHT

Copyright 2010 Keith Grennan.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


1;


1;
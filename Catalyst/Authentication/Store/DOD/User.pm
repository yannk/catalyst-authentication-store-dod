package Catalyst::Authentication::Store::DOD::User;

use strict;
use warnings;
use Data::Dumper;
use base qw/Catalyst::Authentication::User/;
use base qw/Class::Accessor::Fast/;

BEGIN {
    __PACKAGE__->mk_accessors(qw/_config _user _roles/);
}


## XXX I should provide API/config compat with DBIx::Class to facilitate migration

sub new {
    my ( $class, $config, $c) = @_;

    my $self = {
        _config => $config,
        _roles  => undef,
        _user   => undef
    };
    
    bless $self, $class;
    return $self;
}


sub load_model {
    my ($self, $model) = @_;
    warn "loaded $model";
    $self->_user($model);
}

sub from_authinfo {
    my ($self, $authinfo, $c) = @_;
    
    my $user  = $c->model( $c->_config->{user_class} );
    my %args  = ( limit => 1 );
    my %terms = map  { $_ => $authinfo->{$_} }
                grep { $user->has_column($_) }
                keys %$authinfo;

    my @users = $user->search(\%terms, \%args);
    $self->load_model($users[0]);

    if ($self->get_object) {
        return $self;
    } else {
        return undef;
    }
}

sub supported_features {
    my $self = shift;

    return {
        session => 1,
        roles   => 1,
    };
}

sub roles {
    my ( $self ) = shift;
    ## this used to load @wantedroles - but that doesn't seem to be used by the roles plugin, so I dropped it.

    ## shortcut if we have already retrieved them
    if (ref $self->_roles eq 'ARRAY') {
        return(@{$self->_roles});
    }
    
    my @roles = ();
    if (exists($self->_config->{'role_column'})) {
        my $role_data = $self->get($self->_config->{'role_column'});
        if ($role_data) { 
            @roles = split /[ ,\|]+/, $self->get($self->_config->{'role_column'});
        }
        $self->_roles(\@roles);
    } elsif (exists($self->_config->{'role_relation'})) {
        my $relation = $self->_config->{'role_relation'};
        if ($self->_user->$relation->result_source->has_column($self->_config->{'role_field'})) {
            @roles = map { $_->get_column($self->_config->{'role_field'}) } $self->_user->$relation->search(undef, { columns => [ $self->_config->{'role_field'}]})->all();
            $self->_roles(\@roles);
        } else {
            Catalyst::Exception->throw("role table does not have a column called " . $self->_config->{'role_field'});
        }
    } else {
        Catalyst::Exception->throw("user->roles accessed, but no role configuration found");
    }

    return @{$self->_roles};
}

sub for_session {
    my $self = shift;
    
    ## add a config flag, because personnaly
    ## I only care about the pk in the session XXX
    return unless $self->_user;
    return $self->_user->deflate->{columns};
}

sub from_session {
    my ($self, $frozenuser, $c) = @_;
    
    ## if use_userdata_from_session is defined in the config, we fill in the user data from the session.
    if (exists($self->_config->{'use_userdata_from_session'}) && $self->_config->{'use_userdata_from_session'} != 0) {
        my $obj = $self->resultset->new_result({ %$frozenuser });
        $obj->in_storage(1);
        $self->_user($obj);
        return $self;
    } else {
    #    return $self->load( { $self->config->{'id_field'} => $frozenuser->{$self->config->{'id_field'}} }, $c);
        my $model = $c->model( $c->_config->{user_class} );
        my $pk = [ map { $frozenuser->{$_} } @{ $model->primary_key_tuple }];
        $self->load_model( $model->lookup($pk) );
        return $self;
    }
}

## I wonder how this is useful, but implementing it
## since base class requires it. XXX
sub get {
    my ($self, $field) = @_;
    
    my $user = $self->_user;
    return unless $user;
    if ($user->can($field)) {
        return $user->$field;
    } else {
        return undef;
    }
}

sub get_object {
    my ($self, $force) = @_;
    
    ## XXX?
    if ($force) {
        $self->_user->discard_changes;
    }

    return $self->_user;
}

sub obj {
    my ($self, $force) = @_;
    
    return $self->get_object($force);
}

sub auto_create {
    my $self = shift;
#    $self->_user( $self->resultset->auto_create( @_ ) );
    return $self;
}

sub auto_update {
    my $self = shift;
 #   $self->_user->auto_update( @_ );
}

sub AUTOLOAD {
    my $self = shift;
    (my $method) = (our $AUTOLOAD =~ /([^:]+)$/);
    return if $method eq "DESTROY";

    $self->_user->$method(@_);
}

1;
__END__

=head1 NAME

=head1 AUTHOR

Yann Kerherve (yannk@cpan.org)

=cut


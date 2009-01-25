package Catalyst::Authentication::Store::DOD;

use strict;
use warnings;
use base qw/Class::Accessor::Fast/;

our $VERSION= "0.01";


BEGIN {
    __PACKAGE__->mk_accessors(qw/config/);
}

sub user_class { q/Catalyst::Authentication::Store::DOD::User/ }

sub new {
    my ($class, $config, $app) = @_;

    ## make sure the search class is loaded.
    Catalyst::Utils::ensure_class_loaded( $class->user_class );
    Catalyst::Utils::ensure_class_loaded( $config->{search_class} )
        if $config->{search_class};

    my $self = {
        config => $config,
    };

    bless $self, $class;
}

sub from_session {
    my ($self, $c, $frozenuser) = @_;

    my $user = $self->user_class->new($self->config, $c);
    return $user->from_session($frozenuser, $c);
}

sub for_session {
    my ($self, $c, $user) = @_;
    
    return $user->for_session($c);
}

sub find_user {
    my ($self, $authinfo, $c) = @_;
    
    my $user = $self->user_class->new($self->config, $c);
    if (my $search_class = $self->config->{search_class}) {
        my $model = $search_class->from_authinfo($authinfo, $c);
        $user->load_model($model) if $model;
    }
    else {
        $user->from_authinfo($authinfo, $c);
    }
    return $user;
}


sub user_supports {
    my $self = shift;
    return $self->user_class->supports( @_ );
}

sub auto_create_user {
    my( $self, $authinfo, $c ) = @_;

    return $self->user_class->auto_create( $authinfo, $c );
}

sub auto_update_user {
    my( $self, $authinfo, $c, $res ) = @_;

    # XXX
    $res->auto_update( $authinfo, $c );
    return $res;
}

"Data::ObjectDriver rocks your data";

__END__

=head1 NAME

Catalyst::Authentication::Store::DOD - A storage class for Catalyst Authentication using Data::ObjectDriver

=head1 DESCRIPTION

The documentation there is not accurate. comes from another module
incomplete... that's why this is not on CPAN.

=head1 SYNOPSIS

    use Catalyst qw/
                    Authentication
                    Authorization::Roles/;

    __PACKAGE__->config->{authentication} = 
                    {  
                        default_realm => 'members',
                        realms => {
                            members => {
                                credential => {
                                    class => 'Password',
                                    password_field => 'password',
                                    password_type => 'clear'
                                },
                                store => {
                                    class => 'DBIx::Class',
                                    user_class => 'MyApp::User',
                                    id_field => 'user_id',
                                    role_relation => 'roles',
                                    role_field => 'rolename',                   
                                }
                            }
                        }
                    };

    # Log a user in:
    
    sub login : Global {
        my ( $self, $c ) = @_;
        
        $c->authenticate({  
                          username => $c->req->params->username,
                          password => $c->req->params->password,
                          status => [ 'registered', 'loggedin', 'active']
                          }))
    }
    
    # verify a role 
    
    if ( $c->check_user_roles( 'editor' ) ) {
        # do editor stuff
    }
    
=head1 DESCRIPTION

Frankly this class has no DOD specific bits in it.

=head1 CONFIGURATION

=over 4

=item class

Class is part of the core Catalyst::Plugin::Authentication module, it
contains the class name of the store to be used.

=item user_class

Contains the class name (as passed to $c->model()) of the DBIx::Class schema
to use as the source for user information.  This config item is B<REQUIRED>.

=item id_field

Contains the field name containing the unique identifier for a user.  This is 
used when storing and retrieving a user from the session.  The value in this
field should correspond to a single user in the database.  Defaults to 'id'.

=item role_column

If your role information is stored in the same table as the rest of your user
information, this item tells the module which field contains your role
information.  The DBIx::Class authentication store expects the data in this
field to be a series of role names separated by some combination of spaces, 
commas or pipe characters.  

=item role_relation

If your role information is stored in a separate table, this is the name of
the relation that will lead to the roles the user is in.  If this is 
specified then a role_field is also required.  Also when using this method
it is expected that your role table will return one row for each role 
the user is in.

=item role_field

This is the name of the field in the role table that contains the string 
identifying the role.  

=item ignore_fields_in_find

This item is an array containing fields that may be passed to the
$c->authenticate() routine (and therefore find_user in the storage class), but
which should be ignored when creating the DBIx::Class search to retrieve a
user. This makes it possible to avoid problems when a credential requires an
authinfo element whose name overlaps with a column name in your users table.
If this doesn't make sense to you, you probably don't need it.

=item use_userdata_from_session

Under normal circumstances, on each request the user's data is re-retrieved 
from the database using the primary key for the user table.  When this flag 
is set in the configuration, it causes the DBIx::Class store to avoid this
database hit on session restore.  Instead, the user object's column data 
is retrieved from the session and used as-is.  

B<NOTE>: Since the user object's column
data is only stored in the session during the initial authentication of 
the user, turning this on can potentially lead to a situation where the data
in $c->user is different from what is stored the database.  You can force
a reload of the data from the database at any time by calling $c->user->get_object(1);
Note that this will update $c->user for the remainder of this request.  
It will NOT update the session.  If you need to update the session
you should call $c->update_user_in_session() as well.  

=item store_user_class

This allows you to override the authentication user class that the 
DBIx::Class store module uses to perform it's work.  Most of the
work done in this module is actually done by the user class, 
L<Catalyst::Authentication::Store::DBIx::Class::User>, so
overriding this doesn't make much sense unless you are using your
own class to extend the functionality of the existing class.  
Chances are you do not want to set this.

=back

=head1 SEE ALSO

L<Catalyst::Plugin::Authentication>, L<Catalyst::Plugin::Authentication::Internals>,
and L<Catalyst::Plugin::Authorization::Roles>

=cut


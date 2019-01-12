import datetime
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class OpenIdConnectBackend(ModelBackend):
    """
    This backend checks a previously performed OIDC authentication.
    If it is OK and the user already exists in the database, it is returned.
    If it is OK and user does not exist in the database, it is created and returned unless setting
        OIDC_CREATE_UNKNOWN_USER is False.
    In all other cases, None is returned.
    """

    def authenticate(self, request, **kwargs):
        user = None
        if not kwargs or 'sub' not in kwargs.keys():
            return user

        UserModel = get_user_model()
        username = self.clean_username(kwargs['employee_number'])

        # Some OP may actually choose to withhold some information, so we must test if it is present
        openid_data = {'last_login': datetime.datetime.now()}
        if 'first_name' in kwargs.keys():
            openid_data['first_name'] = kwargs['first_name']
        if 'given_name' in kwargs.keys():
            openid_data['first_name'] = kwargs['given_name']
        if 'christian_name' in kwargs.keys():
            openid_data['first_name'] = kwargs['christian_name']
        if 'family_name' in kwargs.keys():
            openid_data['last_name'] = kwargs['family_name']
        if 'last_name' in kwargs.keys():
            openid_data['last_name'] = kwargs['last_name']
        if 'email' in kwargs.keys():
            openid_data['email'] = kwargs['email']

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if getattr(settings, 'OIDC_CREATE_UNKNOWN_USER', True):
            args = {UserModel.USERNAME_FIELD: username, 'defaults': openid_data, }
            user, created = UserModel.objects.update_or_create(**args)
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = UserModel.objects.get_by_natural_key(username)
            except UserModel.DoesNotExist:
                return None
        return user

    def clean_username(self, username):
        """
        Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, returns the username unchanged.
        """
        return username

    def configure_user(self, user):
        """
        Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user

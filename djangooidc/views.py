# coding: utf-8

import logging
from urllib.parse import parse_qs

from django import forms
from django.conf import settings
from django.contrib.auth import logout as auth_logout, authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden, JsonResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render_to_response, resolve_url
from django.template import RequestContext
from django.urls import reverse
from oic.exception import PyoidcError
from oic.oic.message import IdToken, EndSessionRequest

from djangooidc.oidc import OIDCClients, OIDCError

logger = logging.getLogger(__name__)

CLIENTS = OIDCClients(settings)


# Step 1: provider choice (form). Also - Step 2: redirect to OP. (Step 3 is OP business.)
class DynamicProvider(forms.Form):
    hint = forms.CharField(required=True, label='OpenID Connect full login', max_length=250)


def openid(request, op_name=None):
    client = None
    request.session["next"] = request.GET["next"] if "next" in request.GET.keys() else "/"
    try:
        dyn = settings.OIDC_ALLOW_DYNAMIC_OP or False
    except:
        dyn = True

    try:
        template_name = settings.OIDC_LOGIN_TEMPLATE
    except AttributeError:
        template_name = 'djangooidc/login.html'

    # Internal login?
    if request.method == 'POST' and "internal_login" in request.POST:
        return redirect_to_login(request.get_full_path())
    else:
        ilform = AuthenticationForm()

    # Try to find an OP client either from the form or from the op_name URL argument
    if request.method == 'GET' and op_name is not None:
        client = CLIENTS[op_name]
        request.session["op"] = op_name

    if request.method == 'POST' and dyn:
        form = DynamicProvider(request.POST)
        if form.is_valid():
            try:
                client = CLIENTS.dynamic_client(form.cleaned_data["hint"])
                request.session["op"] = client.provider_info["issuer"]
            except Exception as e:
                logger.exception("could not create OOID client")
                return render_to_response("djangooidc/error.html", {"error": e})
    else:
        form = DynamicProvider()

    # If we were able to determine the OP client, just redirect to it with an authentication request
    if client:
        try:
            return client.create_authn_request(request.session)
        except Exception as e:
            return render_to_response("djangooidc/error.html", {"error": e})

    # Otherwise just render the list+form.
    return render_to_response(template_name,
                              {"op_list": [i for i in settings.OIDC_PROVIDERS.keys() if i], 'dynamic': dyn,
                               'form': form, 'ilform': ilform, "next": request.session["next"]},
                              context_instance=RequestContext(request))


# Step 4: analyze the token returned by the OP
def authz_cb(request):
    client_idx = request.COOKIES.get('OP')
    if client_idx:
        client = CLIENTS[client_idx]
    else:
        # return the first (default) client
        client = CLIENTS[list(settings.OIDC_PROVIDERS)[0]]

    try:
        query = parse_qs(request.META['QUERY_STRING'])
        userinfo = client.callback(query, request.session)
        # removing nonce, state cookies. they're essentially worthless at this point, but let's remove them for
        # security purposes nevertheless.
        [request.COOKIES.pop(k, None) for k in ['STATE', 'NONCE']]
        request.session["userinfo"] = userinfo
        user = authenticate(request, **userinfo)
        if not user:
            raise Exception('this login is not valid in this application')
        login(request, user)
        return redirect(request.COOKIES.get('NEXT'))
    except OIDCError as e:
        return render_to_response("djangooidc/error.html", {"error": e, "callback": query})
    except:
        # Any exception during authorization, present them with an error page
        return redirect(reverse("generic_error"))


def refresh(request):
    # Get default client
    client_idx = request.session.get('op')
    if client_idx:
        client = CLIENTS[client_idx]
    else:
        client = CLIENTS[list(settings.OIDC_PROVIDERS)[0]]
    try:
        refresh_token = request.GET.get('refresh_token') or request.COOKIES.get('REFRESH_TOKEN') \
                        or request.session.get('refresh_token')
        if refresh_token is None:
            return HttpResponseBadRequest("No refresh token found.")
        tokens = client.refresh_access_token(request.session, refresh_token)
        response = JsonResponse(tokens)
        response.set_cookie("ACCESS_TOKEN", tokens['access_token'])
        response.set_cookie("REFRESH_TOKEN", tokens['refresh_token'])
    except OIDCError as error:
        return HttpResponseForbidden(error)
    return response


def logout(request, next_page=None):
    client_idx = request.COOKIES.get('OP', request.session.get('op', list(settings.OIDC_PROVIDERS)[0]))
    client = CLIENTS[client_idx]

    # User is by default NOT redirected to the app - it stays on an OP page after logout.
    # Here we determine if a redirection to the app was asked for and is possible.
    if next_page is None and "next" in request.GET.keys():
        next_page = request.GET['next']
    if next_page is None and "next" in request.session.keys():
        next_page = request.session['next']
    extra_args = {}
    if "post_logout_redirect_uris" in client.registration_response.keys() and len(
            client.registration_response["post_logout_redirect_uris"]) > 0:
        if next_page is not None:
            # First attempt a direct redirection from OP to next_page
            next_page_url = resolve_url(next_page)
            urls = [url for url in client.registration_response["post_logout_redirect_uris"] if next_page_url in url]
            if len(urls) > 0:
                extra_args["post_logout_redirect_uri"] = urls[0]
            else:
                # It is not possible to directly redirect from the OP to the page that was asked for.
                # We will try to use the redirection point - if the redirection point URL is registered that is.
                next_page_url = resolve_url('openid_logout_cb')
                urls = [url for url in client.registration_response["post_logout_redirect_uris"] if
                        next_page_url in url]
                if len(urls) > 0:
                    extra_args["post_logout_redirect_uri"] = urls[0]
                else:
                    # Just take the first registered URL as a desperate attempt to come back to the application
                    extra_args["post_logout_redirect_uri"] = client.registration_response["post_logout_redirect_uris"][0]
    else:
        # No post_logout_redirect_uris registered at the OP - no redirection to the application is possible anyway
        pass

    # Redirect client to the OP logout page
    try:
        request_args = None
        if 'id_token' in request.session.keys():
            request_args = {'id_token': IdToken(**request.session['id_token'])}

        # Adding logic to redirect user to the OIC registered logout url instead of attempting to sign out on behalf of
        # the user. Some IDPs require that
        state = request.COOKIES.get("STATE", request.session.get("state", None))
        if client.registration_response.get("redirect_on_logout"):
            url, body, ht_args, csi = client.request_info(request=EndSessionRequest, method="GET",
                                                          request_args=request_args, extra_args=extra_args, scope="",
                                                          state=state)
            return HttpResponseRedirect(url)

        res = client.do_end_session_request(state=state, extra_args=extra_args, request_args=request_args)
        resp = HttpResponse(content_type=res.headers.get("content-type", None), status=res.status_code,
                            content=res._content)
        for key, val in res.headers.items():
            resp[key] = val
        return resp
    except PyoidcError:
        # Probably couldn't get session variables or something. It's okay, just make forward them back to log out page.
        return HttpResponseRedirect(reverse("openid_with_op_name", kwargs={'op_name': client_idx}))
    finally:
        # Always remove Django session stuff - even if not logged out from OP. Don't wait for the callback as it may never come.
        auth_logout(request)
        if next_page:
            request.session['next'] = next_page


def logout_cb(request):
    """ Simple redirection view: after logout, just redirect to a parameter value inside the session """
    next = request.session["next"] if "next" in request.session.keys() else "/"
    return redirect(next)

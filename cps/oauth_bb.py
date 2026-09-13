# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#    Copyright (C) 2018-2019 OzzieIsaacs, cervinko, jkrehm, bodybybuddha, ok11,
#                            andy29485, idalin, Kyosfonica, wuqi, Kennyl, lemmsh,
#                            falgh1, grunjol, csitko, ytils, xybydy, trasba, vrabe,
#                            ruben-herold, marblepebble, JackED42, SiphonSquirrel,
#                            apetresc, nanu-c, mutschler
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>

import json
from functools import wraps
from urllib.parse import urljoin

import requests
from flask import session, request, make_response, abort
from flask import Blueprint, flash, redirect, url_for
from flask_babel import gettext as _
from flask_dance.consumer import oauth_authorized, oauth_error, OAuth2ConsumerBlueprint
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2 import TokenExpiredError, InvalidGrantError
from .cw_login import login_user, current_user
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import func
from .usermanagement import user_login_required

from . import constants, logger, config, app, ub

try:
    from .oauth import OAuthBackend, backend_resultcode
except NameError:
    pass


oauth_check = {}
oauthblueprints = []
oauth = Blueprint('oauth', __name__)
log = logger.create()
generic = None


def oauth_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if config.config_login_type == constants.LOGIN_OAUTH:
            return f(*args, **kwargs)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            data = {'status': 'error', 'message': 'Not Found'}
            response = make_response(json.dumps(data, ensure_ascii=False))
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response, 404
        abort(404)

    return inner


def register_oauth_blueprint(cid, show_name):
    oauth_check[cid] = show_name


def register_user_with_oauth(user=None):
    all_oauth = {}
    for oauth_key in oauth_check.keys():
        if str(oauth_key) + '_oauth_user_id' in session and session[str(oauth_key) + '_oauth_user_id'] != '':
            all_oauth[oauth_key] = oauth_check[oauth_key]
    if len(all_oauth.keys()) == 0:
        return
    if user is None:
        flash(_("Register with %(provider)s", provider=", ".join(list(all_oauth.values()))), category="success")
    else:
        for oauth_key in all_oauth.keys():
            # Find this OAuth token in the database, or create it
            query = ub.session.query(ub.OAuth).filter_by(
                provider=oauth_key,
                provider_user_id=session[str(oauth_key) + "_oauth_user_id"],
            )
            try:
                oauth_key = query.one()
                oauth_key.user_id = user.id
            except NoResultFound:
                # no found, return error
                return
            ub.session_commit("User {} with OAuth for provider {} registered".format(user.name, oauth_key))


def logout_oauth_user():
    for oauth_key in oauth_check.keys():
        if str(oauth_key) + '_oauth_user_id' in session:
            session.pop(str(oauth_key) + '_oauth_user_id')


def oauth_update_token(provider_id, token, provider_user_id):
    session[provider_id + "_oauth_user_id"] = provider_user_id
    session[provider_id + "_oauth_token"] = token

    # Find this OAuth token in the database, or create it
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    )
    try:
        oauth_entry = query.one()
        # update token
        oauth_entry.token = token
    except NoResultFound:
        oauth_entry = ub.OAuth(
            provider=provider_id,
            provider_user_id=provider_user_id,
            token=token,
        )
    ub.session.add(oauth_entry)
    ub.session_commit()

    # Disable Flask-Dance's default behavior for saving the OAuth token
    # Value differrs depending on flask-dance version
    return backend_resultcode


def bind_oauth_or_register(provider_id, provider_user_id, redirect_url, provider_name):
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    )
    try:
        oauth_entry = query.first()
        # already bind with user, just login
        if oauth_entry.user:
            # If a user is already logged in and it's a different account, reject the link
            # to prevent account takeover via shared OAuth identities
            if current_user and current_user.is_authenticated and oauth_entry.user_id != current_user.id:
                flash(_("This %(oauth)s account is already linked to a different user",
                        oauth=provider_name), category="error")
                log.warning("User %s tried to link OAuth account already bound to user %s",
                            current_user.id, oauth_entry.user_id)
                return redirect(url_for('web.profile'))
            login_user(oauth_entry.user)
            log.debug("You are now logged in as: '%s'", oauth_entry.user.name)
            flash(_("Success! You are now logged in as: %(nickname)s", nickname=oauth_entry.user.name),
                  category="success")
            return redirect(url_for('web.index'))
        else:
            # bind to current user
            if current_user and current_user.is_authenticated:
                oauth_entry.user = current_user
                try:
                    ub.session.add(oauth_entry)
                    ub.session.commit()
                    flash(_("Link to %(oauth)s Succeeded", oauth=provider_name), category="success")
                    log.info("Link to {} Succeeded".format(provider_name))
                    return redirect(url_for('web.profile'))
                except Exception as ex:
                    log.error_or_exception(ex)
                    ub.session.rollback()
            else:
                flash(_("Login failed, No User Linked With OAuth Account"), category="error")
            log.info('Login failed, No User Linked With OAuth Account')
            return redirect(url_for('web.login'))
            # return redirect(url_for('web.login'))
            # if config.config_public_reg:
            #   return redirect(url_for('web.register'))
            # else:
            #    flash(_("Public registration is not enabled"), category="error")
            #    return redirect(url_for(redirect_url))
    except (NoResultFound, AttributeError):
        return redirect(url_for(redirect_url))


def get_oauth_status():
    status = []
    query = ub.session.query(ub.OAuth).filter_by(
        user_id=current_user.id,
    )
    try:
        oauths = query.all()
        for oauth_entry in oauths:
            status.append(int(oauth_entry.provider))
        return status
    except NoResultFound:
        return None


def unlink_oauth(provider):
    if request.host_url + 'me' != request.referrer:
        pass
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider,
        user_id=current_user.id,
    )
    try:
        oauth_entry = query.one()
        if current_user and current_user.is_authenticated:
            oauth_entry.user = current_user
            try:
                ub.session.delete(oauth_entry)
                ub.session.commit()
                logout_oauth_user()
                flash(_("Unlink to %(oauth)s Succeeded", oauth=oauth_check[provider]), category="success")
                log.info("Unlink to {} Succeeded".format(oauth_check[provider]))
            except Exception as ex:
                log.error_or_exception(ex)
                ub.session.rollback()
                flash(_("Unlink to %(oauth)s Failed", oauth=oauth_check[provider]), category="error")
    except NoResultFound:
        log.warning("oauth %s for user %d not found", provider, current_user.id)
        flash(_("Not Linked to %(oauth)s", oauth=provider), category="error")
    return redirect(url_for('web.profile'))


def _absolute_url(base_url, url):
    """Resolve a possibly relative endpoint URL against the issuer base URL"""
    if not url or url.startswith(("http://", "https://")) or not base_url:
        return url
    return urljoin(base_url + "/", url.lstrip("/"))


def _resolve_generic_endpoints(element):
    """Resolve the endpoints of the generic provider, preferring the OIDC discovery document"""
    base_url = (element.get('oauth_base_url') or "").strip().rstrip("/")
    element['oauth_issuer'] = base_url
    if base_url:
        discovery_url = base_url if base_url.endswith("/.well-known/openid-configuration") \
            else base_url + "/.well-known/openid-configuration"
        try:
            metadata = requests.get(discovery_url, timeout=10)
            if metadata.ok:
                issuer_metadata = metadata.json()
                element['oauth_auth_url'] = issuer_metadata.get("authorization_endpoint")
                element['oauth_token_url'] = issuer_metadata.get("token_endpoint")
                element['userinfo_url'] = issuer_metadata.get("userinfo_endpoint")
                return True
            log.warning("Discovery document request to %s failed with status code %d",
                        discovery_url, metadata.status_code)
        except Exception as ex:
            log.warning("Failed to fetch OIDC discovery document from %s: %s", discovery_url, ex)
    auth_url = _absolute_url(base_url, (element.get('oauth_auth_url') or "").strip())
    token_url = _absolute_url(base_url, (element.get('oauth_token_url') or "").strip())
    if auth_url and token_url:
        # Manually configured endpoints (Keycloak style relative paths); the userinfo endpoint
        # is taken from the well-known Keycloak path in this case
        element['oauth_auth_url'] = auth_url
        element['oauth_token_url'] = token_url
        element['userinfo_url'] = base_url + "/protocol/openid-connect/userinfo" if base_url else None
        return bool(element['userinfo_url'])
    return False


def bind_generic_user(account_info):
    provider_id = str(oauthblueprints[2]['id'])
    provider_user_id = str(account_info.get("sub") or account_info.get("id") or "")
    if not provider_user_id:
        flash(_("Failed to fetch user info from %(provider)s.",
                provider=oauthblueprints[2].get('login_button') or "generic OAuth"), category="error")
        return redirect(url_for('web.login'))
    oauth_entry = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    ).first()
    if oauth_entry is None:
        # The oauth_authorized handler normally stored the token just before, rebuild it if it is missing
        oauth_update_token(provider_id, generic.session.token, provider_user_id)
        oauth_entry = ub.session.query(ub.OAuth).filter_by(
            provider=provider_id,
            provider_user_id=provider_user_id,
        ).first()
    if oauth_entry is not None and oauth_entry.user is None:
        user = _match_or_create_generic_user(account_info)
        if user is None:
            return redirect(url_for('web.login'))
        oauth_entry.user = user
        try:
            ub.session.add(oauth_entry)
            ub.session.commit()
        except Exception as ex:
            log.error_or_exception(ex)
            ub.session.rollback()
            flash(_("Generic OAuth error, please retry later."), category="error")
            return redirect(url_for('web.login'))
    return bind_oauth_or_register(provider_id, provider_user_id, 'web.login', 'generic')


def _match_or_create_generic_user(account_info):
    username_mapper = oauthblueprints[2].get('username_mapper') or "preferred_username"
    email_mapper = oauthblueprints[2].get('email_mapper') or "email"
    username = str(account_info.get(username_mapper) or "").strip()
    email = str(account_info.get(email_mapper) or "").strip()

    # The email address is the only safe joining key, matching by name alone could take over foreign accounts
    if email:
        user = ub.session.query(ub.User).filter(func.lower(ub.User.email) == email.lower()).first()
        if user is not None:
            return user

    if not oauthblueprints[2].get('auto_create_user'):
        flash(_("This %(provider)s account is not linked to any user.",
                provider=oauthblueprints[2].get('login_button') or "generic OAuth"), category="error")
        log.warning("No local user is linked to the generic OAuth/OIDC identity (username: '%s', email: '%s')",
                    username, email)
        return None

    if not username or not email:
        flash(_("Automatic registration is not possible, the %(provider)s account does not expose username and email.",
                provider=oauthblueprints[2].get('login_button') or "generic OAuth"), category="error")
        return None

    from .helper import check_email, check_username, generate_random_password
    from werkzeug.security import generate_password_hash
    try:
        username = check_username(username)
        email = check_email(email)
    except Exception as ex:
        flash(str(ex), category="error")
        return None

    content = ub.User()
    content.name = username
    content.email = email
    content.password = generate_password_hash(generate_random_password(config.config_password_min_length))
    content.role = config.config_default_role
    content.locale = config.config_default_locale
    content.sidebar_view = config.config_default_show
    content.allowed_tags = config.config_allowed_tags
    content.denied_tags = config.config_denied_tags
    content.allowed_column_value = config.config_allowed_column_value
    content.denied_column_value = config.config_denied_column_value
    try:
        ub.session.add(content)
        ub.session.commit()
    except Exception as ex:
        ub.session.rollback()
        log.error_or_exception(ex)
        flash(_("Oops! An unknown error occurred. Please try again later."), category="error")
        return None
    log.info("User '%s' has been auto-created via the generic OAuth/OIDC provider", content.name)
    return content


def generate_oauth_blueprints():
    global generic

    if not ub.session.query(ub.OAuthProvider).count():
        for provider in ("github", "google", "generic"):
            oauthProvider = ub.OAuthProvider()
            oauthProvider.provider_name = provider
            oauthProvider.active = False
            ub.session.add(oauthProvider)
            ub.session_commit("{} Blueprint Created".format(provider))

    # Databases created before the generic provider existed need the row to be added
    generic_provider = ub.session.query(ub.OAuthProvider).filter(ub.OAuthProvider.provider_name == 'generic').first()
    if generic_provider is None:
        generic_provider = ub.OAuthProvider()
        generic_provider.provider_name = "generic"
        generic_provider.active = False
        ub.session.add(generic_provider)
        ub.session_commit("generic Blueprint Created")

    oauth_ids = ub.session.query(ub.OAuthProvider).all()
    ele1 = dict(provider_name='github',
                id=oauth_ids[0].id,
                active=oauth_ids[0].active,
                oauth_client_id=oauth_ids[0].oauth_client_id,
                scope=None,
                oauth_client_secret=oauth_ids[0].oauth_client_secret,
                obtain_link='https://github.com/settings/developers')
    ele2 = dict(provider_name='google',
                id=oauth_ids[1].id,
                active=oauth_ids[1].active,
                scope=["https://www.googleapis.com/auth/userinfo.email"],
                oauth_client_id=oauth_ids[1].oauth_client_id,
                oauth_client_secret=oauth_ids[1].oauth_client_secret,
                obtain_link='https://console.developers.google.com/apis/credentials')
    ele3 = dict(provider_name='generic',
                id=generic_provider.id,
                active=generic_provider.active,
                oauth_client_id=generic_provider.oauth_client_id,
                oauth_client_secret=generic_provider.oauth_client_secret,
                oauth_base_url=generic_provider.oauth_base_url,
                oauth_auth_url=generic_provider.oauth_auth_url,
                oauth_token_url=generic_provider.oauth_token_url,
                scope=generic_provider.scope or "openid profile email",
                username_mapper=generic_provider.username_mapper or "preferred_username",
                email_mapper=generic_provider.email_mapper or "email",
                login_button=generic_provider.login_button,
                auto_create_user=generic_provider.auto_create_user,
                obtain_link=None)
    oauthblueprints.append(ele1)
    oauthblueprints.append(ele2)
    oauthblueprints.append(ele3)

    for element in oauthblueprints:
        if element['provider_name'] == 'github':
            blueprint = make_github_blueprint(
                client_id=element['oauth_client_id'],
                client_secret=element['oauth_client_secret'],
                redirect_to="oauth."+element['provider_name']+"_login",
                scope=element['scope']
            )
        elif element['provider_name'] == 'google':
            blueprint = make_google_blueprint(
                client_id=element['oauth_client_id'],
                client_secret=element['oauth_client_secret'],
                redirect_to="oauth."+element['provider_name']+"_login",
                scope=element['scope']
            )
        elif _resolve_generic_endpoints(element):
            blueprint = OAuth2ConsumerBlueprint(
                "generic", __name__,
                client_id=element['oauth_client_id'],
                client_secret=element['oauth_client_secret'],
                scope=element['scope'].split(),
                base_url=element.get('oauth_issuer') or "",
                authorization_url=element['oauth_auth_url'],
                token_url=element['oauth_token_url'],
                redirect_to="oauth." + element['provider_name'] + "_login",
            )
            generic = blueprint
        else:
            log.warning("Generic OAuth/OIDC provider is not usable, "
                        "Discovery/Base URL or fallback endpoints are missing")
            element['blueprint'] = None
            continue
        element['blueprint'] = blueprint
        element['blueprint'].backend = OAuthBackend(ub.OAuth, ub.session, str(element['id']),
                                                    user=current_user, user_required=True)
        app.register_blueprint(blueprint, url_prefix="/login")
        if element['active']:
            register_oauth_blueprint(element['id'], element.get('login_button') or element['provider_name'])
    return oauthblueprints


if ub.oauth_support:
    oauthblueprints = generate_oauth_blueprints()

    @oauth_authorized.connect_via(oauthblueprints[0]['blueprint'])
    def github_logged_in(blueprint, token):
        if not token:
            flash(_("Failed to log in with GitHub."), category="error")
            log.error("Failed to log in with GitHub")
            return False

        resp = blueprint.session.get("/user")
        if not resp.ok:
            flash(_("Failed to fetch user info from GitHub."), category="error")
            log.error("Failed to fetch user info from GitHub")
            return False

        github_info = resp.json()
        github_user_id = str(github_info["id"])
        return oauth_update_token(str(oauthblueprints[0]['id']), token, github_user_id)


    @oauth_authorized.connect_via(oauthblueprints[1]['blueprint'])
    def google_logged_in(blueprint, token):
        if not token:
            flash(_("Failed to log in with Google."), category="error")
            log.error("Failed to log in with Google")
            return False

        resp = blueprint.session.get("/oauth2/v2/userinfo")
        if not resp.ok:
            flash(_("Failed to fetch user info from Google."), category="error")
            log.error("Failed to fetch user info from Google")
            return False

        google_info = resp.json()
        google_user_id = str(google_info["id"])
        return oauth_update_token(str(oauthblueprints[1]['id']), token, google_user_id)


    if oauthblueprints[2].get('blueprint') is not None:
        @oauth_authorized.connect_via(oauthblueprints[2]['blueprint'])
        def generic_logged_in(blueprint, token):
            if not token:
                flash(_("Failed to log in with %(provider)s.",
                        provider=oauthblueprints[2].get('login_button') or "generic OAuth"), category="error")
                log.error("Failed to log in with generic OAuth/OIDC provider")
                return False

            resp = blueprint.session.get(oauthblueprints[2]['userinfo_url'])
            if not resp.ok:
                flash(_("Failed to fetch user info from %(provider)s.",
                        provider=oauthblueprints[2].get('login_button') or "generic OAuth"), category="error")
                log.error("Failed to fetch user info from generic OAuth/OIDC provider")
                return False

            try:
                generic_info = resp.json()
                generic_user_id = str(generic_info["sub"])
            except (ValueError, KeyError):
                flash(_("Failed to fetch user info from %(provider)s.",
                        provider=oauthblueprints[2].get('login_button') or "generic OAuth"), category="error")
                log.error("User info of the generic OAuth/OIDC provider is missing the mandatory 'sub' claim")
                return False

            return oauth_update_token(str(oauthblueprints[2]['id']), token, generic_user_id)


    # notify on OAuth provider error
    @oauth_error.connect_via(oauthblueprints[0]['blueprint'])
    def github_error(blueprint, error, error_description=None, error_uri=None):
        msg = (
            "OAuth error from {name}! "
            "error={error} description={description} uri={uri}"
        ).format(
            name=blueprint.name,
            error=error,
            description=error_description,
            uri=error_uri,
        )  # ToDo: Translate
        flash(msg, category="error")

    @oauth_error.connect_via(oauthblueprints[1]['blueprint'])
    def google_error(blueprint, error, error_description=None, error_uri=None):
        msg = (
            "OAuth error from {name}! "
            "error={error} description={description} uri={uri}"
        ).format(
            name=blueprint.name,
            error=error,
            description=error_description,
            uri=error_uri,
        )  # ToDo: Translate
        flash(msg, category="error")

    if oauthblueprints[2].get('blueprint') is not None:
        @oauth_error.connect_via(oauthblueprints[2]['blueprint'])
        def generic_error(blueprint, error, error_description=None, error_uri=None):
            msg = (
                "OAuth error from {name}! "
                "error={error} description={description} uri={uri}"
            ).format(
                name=blueprint.name,
                error=error,
                description=error_description,
                uri=error_uri,
            )  # ToDo: Translate
            flash(msg, category="error")


@oauth.route('/link/github')
@oauth_required
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))
    try:
        account_info = github.get('/user')
        if account_info.ok:
            account_info_json = account_info.json()
            return bind_oauth_or_register(oauthblueprints[0]['id'], account_info_json['id'], 'github.login', 'github')
        flash(_("GitHub Oauth error, please retry later."), category="error")
        log.error("GitHub Oauth error, please retry later")
    except (InvalidGrantError, TokenExpiredError) as e:
        flash(_("GitHub Oauth error: {}").format(e), category="error")
        log.error(e)
    return redirect(url_for('web.login'))


@oauth.route('/unlink/github', methods=["GET"])
@user_login_required
def github_login_unlink():
    return unlink_oauth(oauthblueprints[0]['id'])


@oauth.route('/link/google')
@oauth_required
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            account_info_json = resp.json()
            return bind_oauth_or_register(oauthblueprints[1]['id'], account_info_json['id'], 'google.login', 'google')
        flash(_("Google Oauth error, please retry later."), category="error")
        log.error("Google Oauth error, please retry later")
    except (InvalidGrantError, TokenExpiredError) as e:
        flash(_("Google Oauth error: {}").format(e), category="error")
        log.error(e)
    return redirect(url_for('web.login'))


@oauth.route('/unlink/google', methods=["GET"])
@user_login_required
def google_login_unlink():
    return unlink_oauth(oauthblueprints[1]['id'])


@oauth.route('/link/generic')
@oauth_required
def generic_login():
    if generic is None or not generic.authorized:
        return redirect(url_for("generic.login"))
    try:
        resp = generic.session.get(oauthblueprints[2]['userinfo_url'])
        if resp.ok:
            return bind_generic_user(resp.json())
        flash(_("Generic OAuth error, please retry later."), category="error")
        log.error("Generic OAuth error, please retry later")
    except (InvalidGrantError, TokenExpiredError) as e:
        flash(_("Generic OAuth error: {}").format(e), category="error")
        log.error(e)
    return redirect(url_for('web.login'))


@oauth.route('/unlink/generic', methods=["GET"])
@user_login_required
def generic_login_unlink():
    return unlink_oauth(oauthblueprints[2]['id'])

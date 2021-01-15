#!/usr/bin/env python
"""
CGNX script to generate auth token

tanushree@cloudgenix.com

"""
import cloudgenix
import os
import sys
import datetime
import argparse

# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Generate Auth Token'


try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


ROLES = ["super", "viewonly", "secadmin", "nwadmin", "iamadmin"]
rolemap = {
    "super": "tenant_super",
    "viewonly": "tenant_viewonly",
    "secadmin": "tenant_security_admin",
    "nwadmin": "tenant_network_admin",
    "iamadmin": "tenant_iam_admin"
}

def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering Auth Token info
    auth_group = parser.add_argument_group('Auth Token Specific information',
                                           'Information shared here will be used to create an auth token')
    auth_group.add_argument("--roles", "-R", help="Roles. Allowed values: super, viewonly, secadmin, nwadmin, iamadmin. Multiple roles should be comma separated", default=None)
    auth_group.add_argument("--expirationdate", "-ED", help="Expiration Date in format YYYY-MM-DDTHH:MM:SSZ", default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Parse Args
    ############################################################################
    roles = args["roles"]
    role_ds = []
    if roles:
        if "," in roles:
            tmp = roles.split(",")

            for role in tmp:
                if role not in ROLES:
                    print("ERR: Invalid role. Please choose from: super,viewonly,secadmin,nwadmin or iamadmin")
                    sys.exit()
                else:
                    mappedrole = rolemap[role]
                    role_ds.append({"name":mappedrole})
        else:
            if roles in ROLES:
                mappedrole = rolemap[roles]
                role_ds.append({"name":mappedrole})
            else:
                print("ERR: Invalid role. Please choose from: super,viewonly,secadmin,nwadmin or iamadmin")
                sys.exit()


    expirationdate = args["expirationdate"]
    timestamp= None
    if expirationdate:
        if "." in expirationdate:
            utc_dt = datetime.datetime.strptime(expirationdate,  "%Y-%m-%dT%H:%M:%S.%fZ")


        else:
            utc_dt = datetime.datetime.strptime(expirationdate,  "%Y-%m-%dT%H:%M:%SZ")

        # Convert UTC datetime to seconds since the Epoch
        timestamp = (utc_dt - datetime.datetime(1970, 1, 1)).total_seconds()*1000

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Create Auth Token
    ############################################################################
    authdata = {
        "roles": role_ds,
        "expires_utc_ms": timestamp
    }

    operator_id = cgx_session.operator_id

    print("INFO: Creating AUTH Token for operator {} using data {}".format(operator_id, authdata))
    resp = cgx_session.post.authtokens(operator_id=operator_id, data=authdata)
    if resp.cgx_status:
        print("Auth creation successful!")
        authtoken = resp.cgx_content.get("x_auth_token",None)
        print(authtoken)

    else:
        print("ERR: Could not create auth token")
        cloudgenix.jd_detailed(resp)


    ############################################################################
    # Logout to clear session.
    ############################################################################
    cgx_session.get.logout()

    print("INFO: Logging Out")
    sys.exit()

if __name__ == "__main__":
    go()

import datetime
from time import mktime

from flask import Flask, request
import jwt
import requests

from secrets import api_auth_token, jwt_secret_key
from utils import parse_date_time, parse_label
from business import get_user_by_email

app = Flask(__name__)


def decode_auth_token(auth_token):
    # use jwt, jwt_secret_key
    # should be a one liner, but we want you to see how JWTs work

    return jwt.decode(auth_token, jwt_secret_key)


def encode_auth_token(user_id, name, email, scopes):
    # use jwt and jwt_secret_key imported above, and the payload defined below
    # should be a one liner, but we want you to see how JWTs work
    # remember to convert the result of jwt.encode to a string
    # make sure to use .decode("utf-8") rather than str() for this

    # Create payload as dictionary
    payload = {
        'sub': user_id,
        'name': name,
        'email': email,
        'scope': scopes,
        'exp': mktime((datetime.datetime.now() + datetime.timedelta(days=1)).timetuple())
    }

    # Encode using jwt library
    encoded = jwt.encode(payload, jwt_secret_key)

    # Return with utf-8 style
    return encoded.decode("utf-8")


def get_user_from_token():
    # use decode_auth_token above and flask.request imported above
    # should pull token from the Authorization header
    # Authorization: Bearer {token}
    # Where {token} is the token created by the login route

    # Pull Authorization header and parse
    auth = request.headers['Authorization']
    auth_token = auth.split()[1]

    # Return decoded token info
    return decode_auth_token(auth_token)


@app.route('/')
def status():
    return 'API Is Up'


@app.route('/user', methods=['GET'])
def user():

    # Get the user data from the auth/header/jwt
    user = get_user_from_token()

    # Check for token in header
    if not user:
        return {'Message': 'You need a token.'}

    # Return user information
    return {
        'user_id': user['sub'],
        'name': user['name'],
        'email': user['email']
    }


@app.route('/login', methods=['POST'])
def login():
    # use use flask.request to get the json body and get the email and scopes property
    # use the get_user_by_email function to get the user data
    # return a the encoded json web token as a token property on the json response as in the format below
    # we're not actually validitating a password or anything because that would add unneeded complexity

    # Get required params from json
    params = request.json
    user = get_user_by_email(params['email'])

    # Check if the user exists
    if not user:
        return {'Message': 'User does not exist.'}

    # Encode user information with token
    token = encode_auth_token(
        user['id'],
        user['name'],
        user['email'],
        params['scopes']
    )

    # Return token
    return {
        'token': token
    }


@app.route('/widgets', methods=['GET'])
def widgets():
    # accept the following optional query parameters (using the the flask.request object to get the query params)
    # type, created_start, created_end
    # dates will be in iso format (2019-01-04T16:41:24+0200)
    # dates can be parsed using the parse_date_time function written and imported for you above
    # get the user ID from the auth/header
    # verify that the token has the widgets scope in the list of scopes

    # Using the requests library imported above send the following the following request,

    # GET https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}
    # HEADERS
    # Authorization: apiKey {api_auth_token}

    # the api will return the data in the following format

    # [ { "id": 1, "type": "floogle", "created": "2019-01-04T16:41:24+0200" } ]
    # dates can again be parsed using the parse_date_time function

    # filter the results by the query parameters
    # return the data in the format below

    # Get user detail from token
    user = get_user_from_token()

    # Accept optional query params
    params = request.json

    # Check if widgets is in token scope
    if 'widgets' not in user['scope']:

        return {"Message": "You do not have the required access."}

    # Make call to API using secret token
    url = 'https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}'
    format_url = url.format(user_id=user['sub'])
    auth = 'apiKey {api_auth_token}'.format(api_auth_token=api_auth_token)
    response = requests.get(format_url, headers={"Authorization": auth})

    # Check for server response
    if response:

        # Get response content
        widgets = response.json()

        # Filter widget list if optional query parameters exist
        if 'type' in params:
            widgets = [d for d in widgets if d['type'] == params['type']]
        if 'created_start' in params:
            widgets = [d for d in widgets if parse_date_time(d['created']) > parse_date_time(params['created_start'])]
        if 'created_end' in params:
            widgets = [d for d in widgets if parse_date_time(d['created']) < parse_date_time(params['created_end'])]

        # Add additional type_label field to all filtered widgets
        for widget in widgets:
            widget.update({"type_label": parse_label(widget['type'])})

        # Create payload and return to user
        payload = {
            'total_widgets_own_by_user': len(widgets),
            'matching_items': widgets
        }
        return payload

    # Catch any error and return message
    else:
        return {"Message": "Something with wrong with API request."}


if __name__ == '__main__':
    app.run()

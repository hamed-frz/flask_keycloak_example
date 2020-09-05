#import pydevd_pycharm
#pydevd_pycharm.settrace('172.18.0.1', port=2222, stdoutToServer=True, stderrToServer=True)


from uuid import uuid4
import jwt
from flask import Flask, request
from flask import session, make_response, g
from flask import current_app
from flask_cors import CORS, cross_origin
#from keycloak_utils import get_admin, create_user, get_oidc, get_token, check_token
from celery_worker import *
#from app import app
import redis
import json
#import Requests-OAuthlib
from flask_oidc import OpenIDConnect

app = Flask(__name__)
#app.config.from_object('keycloak_flask.settings')
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'CORS_HEADERS':'Content-Type',
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'flask-app',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})
#    'OVERWRITE_REDIRECT_URI': 'http://localhost:8009/private',



redisdb = redis.StrictRedis(host = 'my_demo_app_db', port = '6379', db = '3')
oidc = OpenIDConnect(app)
CORS(app)

#info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
#pr = '*****debug' + info
#print(str(pr))

@app.route('/makedata')
@oidc.require_login
def MakeDataApi():
    name = request.args.get('name', 'hamed')
    number = request.args.get('number', '123456')
    method = request.args.get('method', 'POST')
    timeout = request.args.get('timeout', 10)
    key = str(uuid4())
    # print(key)
    data = '{"name":' + '"' + name + '"' + ',"number":' + '"' + number + '"' + ',"key":' + '"' + key + '"' + '}'
    print(data)
    getWebCelery.delay(data, method)
    localdb = redis.StrictRedis(host = 'my_celery_db', port = '6379', db = '1')
    res_with_key = str(localdb.get(str(key)))
#    res_with_key = str(redisdb.get(str(key)))
    print(str(res_with_key))
    return {"key": key, "data": res_with_key}


@app.route("/getdata", methods=["GET"])
@oidc.accept_token(require_token=True)
def GetData():
    if request.is_json: 
        method = "POST"
        data = request.get_json()
        key = data['key']
        res_json = getDataCelery.delay(data, method)
        res_with_key = str(redisdb.get(str(key)))
        print(str(res_with_key))
        return {"key": key, "data": res_with_key}
    else:
        return {"error": "The request payload is not in JSON format"}

@app.route("/directgetdata", methods=["POST"])
@oidc.accept_token(require_token=True, scopes_required = 'flask:getdata' )
def DirectGetData():
    if request.is_json:
        BASE_URL = 'http://my-app-getdataapi/getdata'
        headers = {"Content-Type":"application/json"}
        url = f'{BASE_URL}'
        method = 'POST'
        data = request.get_json()
        key = data['key']
        data = '{"key":' + '"' + key + '"' + '}'
        res = requests.post( f'{url}', headers = headers, data = data)
#        print(res.raise_for_status())
        res_json = res.json()
        res_json_f = str(json.dumps(res_json))
#        print(str(res_json_f))
        return {"key": key, "data": res_json_f}
    else:
        return {"error": "The request payload is not in JSON format"}


@app.route('/')
def home():
    if oidc.user_loggedin:
        return 'Welcomes %s' %oidc.user_getfield('email')
    else:
        return 'not logged in'


@app.route('/private')
@oidc.require_login
def hello_me():
    """Example for protected endpoint that extracts private information from the OpenID Connect id_token.
       Uses the accompanied access_token to access a backend service.
    """

    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])

    username = info.get('preferred_username')
    email = info.get('email')
    user_id = info.get('sub')
    role = info.get('roles')

#    if user_id in oidc.credentials_store:
    try:
        from oauth2client.client import OAuth2Credentials
        access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
        print('access_token=<%s>' % access_token)

        headers_user = {'Authorization': 'Bearer %s' % (access_token)
                    ,'Content-Type':'application/x-www-form-urlencoded'
                    }
#
'''
        h = {'Content-Type':'application/x-www-form-urlencoded'}
            # YOLO
        url_authorize = 'http://172.18.0.3:8080/auth/realms/My-app/protocol/openid-connect/token'
        data1 = {'grant_type':'client_credentials','client_secret':'6d104638-f3ad-4d20-a67d-a544c2bd72f6','client_id':'flask-app'}
        res_authoriz1 = requests.post(url_authorize, headers=h, data=data1)
        res_json = json.loads(res_authoriz1.content)
        client_access_token = res_json['access_token']
        print(client_access_token)
        headers_client = {'Authorization': 'Bearer %s' % (client_access_token)
                    ,'Content-Type':'application/x-www-form-urlencoded'
                    }
'''
        url_authorize = 'http://172.18.0.3:8080/auth/realms/My-app/protocol/openid-connect/token'
        data = {'grant_type':'urn:ietf:params:oauth:grant-type:uma-ticket', 'audience':'flask-app', 'permission':'access#flask:getdata'}
        res_authoriz = requests.post(url_authorize, headers=headers_user, data= data)
        #print('****debug: authorize res is --> new line:\n\t')
        #print(res_authoriz)
        #print(res_authoriz.headers)
        res_json2 = json.loads(res_authoriz.content)
        access_token2 = res_json['access_token']
        access_token2 = jwt.decode(access_token2,verify=False)
        if res_authoriz.status_code == 200:
            oidc._set_cookie_id_token(access_token2)

        key = 'hj-jalsm-182m-as'
        data = '{"key":' + '"' + key + '"' + '}'
        greeting = requests.post('http://localhost:8009/directgetdata', headers=headers_user, data=data)
        #greeting = requests.post('http://localhost:8009/directgetdata', headers=headers).text
    except:
        print ("Could not access greeting-service")
        oidc.logout()
        greeting = "Hello %s" % (username)
#    else:
#        greeting = 'error'
    

    return ("""code:%s res:%s
                your email is %s and your user_id is %s and role is %s
                
                client_access_token= %s
                access_token_resp= %s!
               <ul>
                 <li><a href="/">Home</a></li>
                 <li><a href="//localhost:8081/auth/realms/pysaar/account?referrer=flask-app&referrer_uri=http://localhost:5000/private&">Account</a></li>
                </ul>""" %
            ( greeting.status_code,str(greeting.json()), email, user_id, role, client_access_token, res_json2))


if __name__ == '__main__':
    app.run('0.0.0.0', 8009)



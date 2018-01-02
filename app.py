from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask_oauthlib.client import OAuth

app = Flask(__name__)

oauth = OAuth(app)

app.config['GOOGLE_ID'] = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Restaurant Menu Application"

app.config['GOOGLE_SECRET'] = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_secret']

app.config['GITHUB_ID'] = json.loads(open('gh_client_secrets.json','r').read())['client_id']
app.config['GITHUB_SECRET'] = json.loads(open('gh_client_secrets.json','r').read())['client_secret']

app.config['SECRET_KEY'] = "UaGGGuWqikQaMIZ1JCn6vJXHIK003YBKlqk8sdzn"

app.debug = True
app.secret_key = app.config.get('SECRET_KEY')

google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

github = oauth.remote_app(
    'github',
    consumer_key=app.config.get('GITHUB_ID'),
    consumer_secret=app.config.get('GITHUB_SECRET'),
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)

# OAUTH helper functions
@google.tokengetter
def get_google_oauth_token():
    return login_session["token"]

@github.tokengetter
def get_github_oauth_token():
    return login_session["token"]


# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.errorhandler(404)
def page_not_found(e):
    return(render_template("error.html", error=404), 404)


@app.errorhandler(410)
def page_gone(e):
    return(render_template("error.html", error=410), 410)


@app.errorhandler(403)
def page_forbidden(e):
    return(render_template("error.html", error=403), 403)


@app.errorhandler(500)
def page_server_error(e):
    return(render_template("error.html", error=500), 500)


@app.route("/")
@app.route("/index")
def index():
    return render_template("home.html")


@app.route("/users/list")
@app.route("/users/list/index")
def userlist():
    users = session.query(User).all()
    return render_template("userlist.html", users=users)

@app.route("/api/categories.json")
@app.route("/api/categories")
def categoriesJson():
    categories = session.query(Category)
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/login')
@app.route("/login/index")
def showLogin():
    return render_template('login.html', ls=login_session)


@app.route("/login/loggedin")
@app.route("/login/loggedin/index")
def showLoggedIn():
    return render_template("loggedin.html", ls=login_session)


@app.route('/login/google')
@app.route('/login/google/index')
def showGoogleLogin():
    return google.authorize(
        callback=url_for('googleAuthorized',
                         _external=True)
    )

@app.route("/login/github")
@app.route("/login/github/index")
def showGithubLogin():
    return github.authorize(callback=url_for('githubAuthorized', _external=True))

@app.route("/login/github/authorized")
@app.route("/login/github/authorized/index")
def githubAuthorized():
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp
        )
    login_session["token"] = (resp['access_token'], '')
    me = github.get('user')
    login_session["provider"] = "github"
    login_session["email"] = me.data["email"]
    login_session["username"] = me.data["name"]
    login_session["link"] = me.data["html_url"]
    login_session["picture"] = me.data["avatar_url"]
    login_session["user_id"] = checkUser(login_session)
    return redirect("/login/loggedin",code=302)


@app.route('/login/google/authorized')
@app.route('/login/google/authorized/index')
def googleAuthorized():
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    login_session["provider"] = "google"
    login_session["token"] = (resp['access_token'], '')
    #checkUser(login_session)
    #login_session["user_id"] = getUserID(login_session["email"])
    me = google.get('userinfo')
    login_session["email"] = me.data["email"]
    login_session["username"] = me.data["name"]
    login_session["link"] = me.data["link"]
    login_session["picture"] = me.data["picture"]
    login_session["user_id"] = checkUser(login_session)
    return redirect("/login/loggedin",code=302)





# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture="")
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def checkUser(ls):
    if getUserID(ls["email"]) is None:
        return createUser(ls)
    else:
        return getUserID(ls["email"])


# Disconnect based on provider
@app.route('/logout')
@app.route('/logout/index')
def logout():
    if(login_session["token"]):
        del login_session["user_id"]
        del login_session["token"]
        del login_session["username"]
        del login_session["provider"]
        del login_session["picture"]
        del login_session["link"]
        flash("You have been logged out!")
        return redirect(url_for("showLogin"), code=302)
    else:
        return render_template("page.html", content="You are not logged in!")


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

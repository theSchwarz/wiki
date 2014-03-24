# (TECHNICAL) DESIGN GOALS
# 1. Write clean, modular code.
# 2. (Almost) Never hit the DB for reads.
# 3. Implement cookies, user accounts, and password hashing myself for learning purposes.

# TO DOs:
# Clean up cookie module so that naming is intuitive. Better break apart methods.
# (Maybe?) Keep state of referrer in generic handler using refferer header rather than refURL query param I have everywhere.
# Integrate some js just for kicks.

import webapp2
import sys 
import os
import cgi
import re
import cookies
import json
import datetime
import logging
from google.appengine.api import memcache
from random import randint
from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.ext import db
import jinja2
import saltyPassword
import data

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False, extensions=['jinja2.ext.autoescape']) 
#autoescape set to False since this is a wiki. does NOT do anything to help server side escaping.

#generic handler class for anytime you want to write a web page. can be used for both get and post.
#have all of your page-specific classes inherit from here, call render with a template name and list of **kwargs to fill in the template values.
class Handler(webapp2.RequestHandler):

    def __init__(self,request,response):
        self.initialize(request,response)
        #Used everywhere to define the path of the page & the user.
        self.page_id = ""
        self.username = ""

        #Control how nav bar links behave
        self.logState = ""
        self.logURL = "" 
        self.editState = ""
        self.editURL = "" 
        self.historyURL = ""

        #Common queries that are used in multiple places.
        self.pageQuery = ""
        self.urlQuery = ""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
        
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login_check(self):
        if not cookies.get_cookie_string(self.request,"username","")[1]:
            self.logState = "login"
            self.logURL = "/login?refURL=%s" % self.request.path[1:]
            logging.info("User is not logged in. Checking for %s" % self.page_id)
            return False
        else:
            self.logURL = "/logout?refURL=%s" % self.request.path[1:]
            logging.info("self.logURL is %s" % self.logURL)
            self.username = cookies.get_usable_cookie_value(self.request,"username","")
            self.logState = "(%s) logout" % self.username
            logging.info("User is logged in. self.username is %s" % self.username)
            return self.username

    #Run this on all pages except /login and /logout
    def startup(self, requestObj):
        self.page_id = self.set_page_id(requestObj)
        logging.info("self.page_id is %s" % self.page_id)
        self.set_history_URL()
        self.login_check()
        self.define_common_queries()

    def set_history_URL(self):
        self.historyURL = "/_history%s" % self.page_id

    def set_page_id(self, requestObj):
        logging.info("path is %s" % requestObj.path)
        page_id = requestObj.path
        for urlMarker in ('/_edit','/_history'):
            if page_id.startswith(urlMarker):
                page_id = page_id[len(urlMarker):]
        return page_id

    def get_query_param(self, getRequestObj, key, defaultStr = ""):
        if key in getRequestObj.params and getRequestObj.params[key]:
            logging.info("%s is %s" % (key,getRequestObj.params[key]))
            val = getRequestObj.params[key]
        elif defaultStr:
            val = defaultStr
        else:
            val = None
        return val

    def log_user_in(self,userObj):
        real_username = userObj.username
        readableUsernameCookie = cookies.get_usable_cookie_value(self.request,real_username,"")
        readableUsernameCookie = real_username
        cookies.set_secure_cookie(self.response,"username",readableUsernameCookie,"/")

    def log_user_out(self):
        cookies.delete_cookie(self.request, self.response, "username","/")

    def define_common_queries(self):
       #Should probably define these in a module. e.g. queries.pageQuery. Didn't know how to do that though because
       #they require arguments that are defined in the handlers (e.g. self.page_id)
       #Is formatting like the below bad habit? Clearly vulnerable to sql injection in the format below, but I'm pretty sure
       #GQL is read only, and only allows one read per function call, and thus doesn't really pose a problem.
       self.pageQuery = "Select * from Entry where url = '%s' and ancestor is Key('URL', '%s') order by created desc" % (self.page_id, self.page_id)
       self.urlQuery = "select * from URL where url = '%s'" % self.page_id



#-------Actual Page Handlers---------#

class WikiPage(Handler):
    def get(self, dont_use_me): 
    #dont_use_me is there because I couldn't figure out how to not pass the URL as a param (GAE automatically does this 
    #when you use a regex in the URL mapping. Tried the syntax to not include it but got stuck. 
        self.startup(self.request)
        query, cacheKey, historyMessage = self.which_version()
        markup = data.read_from_cache_or_db(cacheKey, query, "first")
        if markup:
            self.render("main.html", logState = self.logState, logURL = self.logURL, \
                    editState = "edit", editURL = "/_edit%s" % self.page_id, \
                    history = "history", historyURL = self.historyURL, markup = markup.markup, \
                    historyMessage = historyMessage)
        else:
            self.redirect("/_edit%s" % self.page_id)

    def which_version(self):
        version = self.get_query_param(self.request, "v")
        if version:
            logging.info("version param passed.")
            query = "Select * from Entry where versionNum = %s and Ancestor is Key('URL', '%s')" % (version,self.page_id)
            cacheKey = "_v%s/%s" % (self.page_id, version)
            historyMessage = "Showing revision %s of this page." % version
        else:
            logging.info("No entry ID param was passed.")
            query = self.pageQuery
            cacheKey = self.page_id
            historyMessage = ""
        logging.info("Wiki Query is %s" % query)
        return query, cacheKey, historyMessage

class EditPage(Handler):
    def get(self, dont_use_me):
        self.startup(self.request)
        if self.logState == 'login':
            self.redirect('/login/?refURL=/_edit%s' % self.page_id)
        markupText = data.read_from_cache_or_db(self.page_id, self.pageQuery, "first")
        if markupText:
            self.render("edit.html", logState = self.logState, logURL = self.logURL, \
                        editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                        history = "history", markup = markupText.markup)
        else:
            self.render("edit.html", logState = self.logState, logURL = self.logURL, editState = "view", \
                historyURL = self.historyURL, editURL = "%s" % self.page_id)
        

    def post(self, dont_use_me):

        self.startup(self.request)
        markup = self.request.get('markup')
        if not markup:
            self.render("edit.html", logState = self.logState, logURL = self.logURL, \
                         editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                         history = "history", error = "No blank submissions plz!")
        else:
            #need a urlObj so that entry can specify it as its parent. 
            #this gives us strong consistency in datastore reads, so user will always see what he/she just posted.
            urlObj = data.read_from_cache_or_db(self.page_id, self.urlQuery, "first")
            if not urlObj:
                urlObj = data.URL(url = self.page_id, key_name = self.page_id)
                data.cache_and_db_write(urlObj, {'url_%s' % self.page_id:self.urlQuery})

            versionCount = db.GqlQuery("Select * from Entry where Ancestor \
                                        is Key('URL', '%s')" % self.page_id).count() + 1 #need to hit db for this. will be different for each post. 
           
            dbObj = data.Entry(parent = urlObj.key(), markup = markup, url = self.page_id, createdBy = self.username, versionNum = versionCount)
            cacheDict = {self.page_id:self.pageQuery, "history_%s" % self.page_id:self.pageQuery}
            data.cache_and_db_write(dbObj,cacheDict) 
            self.redirect("%s" % self.page_id)

class HistoryPage(Handler):

    def get(self, dont_use_me):
        self.startup(self.request)
        versions = data.read_from_cache_or_db("history_%s" % self.page_id, self.pageQuery, "all") 
        logging.info("versions is %s" % versions)
        if not versions:
            logging.info("no history found for this page")
            self.render("history.html", logState = self.logState, logURL = self.logURL, \
                        editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                        history = "history", error = "No history for this page yet")
        else:
            logging.info("history found for this page")
            for version in versions:
                #slightly inefficient bc I'm going to iterate through this list once here, and once again on render. 
                #probably doesn't matter since it's such a tiny list? Should I care about this inefficiency?
                if len(version.markup) > 30:
                    version.markup = version.markup[0:40] + "..."
            self.render("history.html", logState = self.logState, logURL = self.logURL, \
                        editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                        history = "history", versions = versions, pageURL = "%s" % self.page_id)

class Welcome(Handler):

    def get(self):
        self.startup(self.request)
        self.render("welcome.html", logState = self.logState, logURL = self.logURL)

class Signup(Handler):

    #to dos: finish post function so that it...
    #   - Do database write in a transaction, rather than checking for username existance in one call, and then writing in a second call
    #        This is bad because state of DB could theoretically change between time of those calls.
    #   - validates that the html inputs are correct (email syntax)
    #   - In a perfect world, we'd wait for a response back from the db saying that the write was successful before setting the cookie.

    def render_main(self, email="", username="", password="",verify="", error=""):
        kwargs = {"email":email, "username":username, "password":password, "verify":verify, "error":error, \
                  "logState":self.logState, "logURl": self.logURL}
        self.render("signup.html",**kwargs)

    def get(self):
        self.startup(self.request)
        self.render_main()

    def post(self):
        self.startup(self.request)
        email = self.request.get("email")
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")

        refURL = str(self.get_query_param(self.request, 'refURL', '/'))

        if password != verify:
            self.render_main(email,username,password,verify,"Make sure your passwords match!")
            return
        elif not password or not verify or not username:
            logging.info("Missing a field")
            self.render_main(email,username,password,verify,"Please fill in every field.")
            return

        newUser = self.create_user(email,username,password)
        if not newUser:
            self.render_main(email,username,password,verify,"That username exists.")
            return
        else:
            self.log_user_in(newUser)
            self.redirect(refURL)

    @db.transactional
    def create_user(self,email,username,password):
        if data.UserDB.get_by_key_name(username):
            return False
        else:
            password = saltyPassword.generate_salted_password(password)
            newUser = data.UserDB(email = email, username = username, password = password, key_name = username)
            newUser.put()
            return newUser

class Login(Handler):

    def render_main(self,username="", password="", error=""):
        kwargs = {"username":username,"password":password, "error":error}
        self.render("login.html", **kwargs)

    def get(self):
        self.render_main()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        if not username or not password:
            error = "invalid username/password combination"
            self.render_main(username, password, error)
            return 

        userQuery = "select * from UserDB where username = '%s'" % username
        user_entity = data.read_from_cache_or_db(username,userQuery,"first")
        #any reason not to cache user objects? Couldn't think of one, but curious.

        if user_entity and saltyPassword.is_valid_password(password,user_entity):
            logging.info('valid username and password found')
            self.log_user_in(user_entity)
            refURL = str(self.get_query_param(self.request, 'refURL', '/'))
            logging.info('refURL is %s' % refURL)
            self.redirect(refURL)   

        else:
            error = "invalid username/password combination"
            self.render_main(username,password,error)

class Logout(Handler):

    def get(self):
        refURL = str(self.get_query_param(self.request, 'refURL', '/'))
        self.log_user_out()
        self.redirect(refURL)

class Test(Handler):
    #I use this for testing out read/write stuff. Just need to add (r"/test/?", Test) to url mapping
    def get(self):
        foo = data.testDB(record = "1")
        foo.put()
        print data.db.GqlQuery("Select * from testDB").get().record
        self.response.out.write("Done")

PAGE_RE = r'(?:/([a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([ (r"/?", Welcome), (r"/signup/?", Signup), (r"/test/?", Test), \
                                       (r"/login/?",Login), (r"/logout/?",Logout), \
                                       ('/_edit' + PAGE_RE, EditPage), ('/_history' + PAGE_RE, HistoryPage), \
                                       (PAGE_RE, WikiPage)], debug=True) 
                                       
def handle_404(request, response, exception):
    response.write("can't find that url")
    response.set_status(404)

def handle_500(request, response, exception):
    response.write("500 error")
    response.set_status(500)

#application.error_handlers[404] = handle_404
#application.error_handlers[500] = handle_500






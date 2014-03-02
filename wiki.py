#TO DOs:
#0) Fix login submit bug where I don't redirect. May relate to #1.
#1) Keep state of referrer in generic handler using refferer header rather than refURL query param I have everywhere.
#2) Move db stuff into separate model.
#3) Clean up the Signup function so that writes are correct. Right now I don't even check if that user exists (Did that a while ago)
#4) Move signup stuff out of here.
#5) Integrate css.
#6) Integrate some js just for kicks.

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

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False, extensions=['jinja2.ext.autoescape']) 

#autoescape set to False since this is a wiki. does NOT do anything to help server side escaping.

#generic handler class for anytime you want to write a web page. can be used for both get and post.
#have all of your page-specific classes inherit from here, call render with a template name and list of **kwargs to fill in the template values.
class Handler(webapp2.RequestHandler):

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
            self.username = cookies.get_usable_cookie_value(self.request, "username", "")
            self.logState = "(%s) logout" % self.username
            logging.info("User is logged in. self.username is %s" % self.username)
            return self.username

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
        if "/_edit" in page_id:
            page_id = page_id[6:]
        if "/_history" in page_id:
            page_id = page_id[9:]
        return page_id

    def get_query_param(self, getRequestObj, key, defaultStr):
        if key in getRequestObj.params:
            logging.info("%s is %s" % (key,getRequestObj.params[key]))
            val = getRequestObj.params[key]
        else:
            val = defaultStr
        return val

    def log_user_in(self,userObj):
        real_username = userObj.username
        readableUsernameCookie = cookies.get_usable_cookie_value(self.request,real_username,"")
        readableUsernameCookie = real_username
        cookies.set_secure_cookie(self.response, "username", readableUsernameCookie, "/")

    def log_user_out(self):
        cookies.delete_cookie(self.request, self.response, "username","/")

    def get(self):
        self.response.out.write("no GET method defined!")


    #------------- DB and Cache Handlers. Should probably put this in own module ------------------------

    def cache_and_db_write(self, dbRecord, cacheDict = {}): 
        #cacheDict should be mappings of strings like {cacheKey: GqlQuery} representing the different
        #caches you want to update with each write, and the corresponding gql query you want to run 
        #to generate the cache value, which will always be a GqlQuery object.
        logging.info("writing to the database")
        try:
            foo = dbRecord.put()
        except:
            print "DB write not done yet!"
        for key in cacheDict:
            logging.info("setting memcache with %s, %s" % (key, cacheDict[key]))
            memcache.set(key, db.GqlQuery(cacheDict[key]))

    def read_from_cache_or_db(self, cacheKey, dbQuery, firstOrAll): 
        #Goal here was to have one standard way to read from the cache/db to ensure I always cache appropriately. 
        #Not sure if this is a good idea or not. Would love fdbk.
        #firstOrAll string specifies whether you want first result from a DB query, or the full list of results.
        #Should be "first" or "all".

        memcacheVal = self.check_memcache(cacheKey, firstOrAll)
        if not memcacheVal:
            return self.check_db(cacheKey, dbQuery, firstOrAll)
        else:
            return memcacheVal

    def check_db(self, cacheKey, dbQuery, firstOrAll):
        logging.info('%s was NOT found in memcache. Checking DB.' % cacheKey)
        data = db.GqlQuery(dbQuery)
        if data.count() < 1: #seems like only way to check for empty db query.
            logging.info('Not in the db.')
            return False
        else:
            logging.info('%s is result from DB.' % data)
            if firstOrAll == "first":
                memcache.set(cacheKey,data)
                return data.get()
            elif firstOrAll == "all":
                memcache.set(cacheKey,data) #pickle cannot make sense of GAE iterable for memcache storage. Need to convert to a list.
                return data.run()

    def check_memcache(self, cacheKey, firstOrAll):
        logging.info('reading %s from memcache' % cacheKey)
        val = memcache.get(cacheKey)
        if val:
            logging.info('found %s in memcache. It is %s' % (cacheKey, val))
            if firstOrAll == "first":
                return val.get()
            elif firstOrAll == "all":
                return list(val.run())
        else:
            logging.info('did not find %s in memcache' % cacheKey)
            return

    def define_common_queries(self):
       #Should probably define these in a module. e.g. queries.pageQuery. Didn't know how to do that though because
       #they require arguments that are defined in the handlers (e.g. self.page_id)
       self.pageQuery = "Select * from Entry where url = '%s' and ancestor is Key('URL', '%s') order by created desc" % (self.page_id, self.page_id)
       self.urlQuery = "select * from URL where url = '%s'" % self.page_id

# -----DB Classes. Probs should be in own module. ---------- #

class Entry (db.Model):
    #When creating an Entry, always specify the corresponding URL as the parent.
    #This maintains consistency between writes to Entries and reads from Entries.
    #This became important when I'd post an entry, get redirected to the main wiki page, and see old results.

    markup = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    url = db.StringProperty(required = True)
    createdBy = db.StringProperty(required = True)

class URL(db.Model):
    url = db.StringProperty(required = True)

class UserDB(db.Model):
    #username is the unique key. When creating a new user, specify 'key_name = username'
    #e.g. foo = Entry(username=usernameStr, pw = pwStr, key_name = usernameStr)
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

#-------Actual Page Classes---------#

class WikiPage(Handler):
    def get(self, dont_use_me): 
    #dont_use_me is there because I couldn't figure out how to not pass the URL as a param.
    #issue is that when you use a regex in url defs for app engine, it passes URL along. I tried the syntax
    #to not include it but got stuck. 
        self.startup(self.request)
        markup = self.read_from_cache_or_db(self.page_id, self.pageQuery, "first")
        if markup:
            #logging.info("Wiki page: markup is %s and markup.markup is %s" % (markup, markup.markup))
            self.render("main.html", logState = self.logState, logURL = self.logURL, \
                    editState = "edit", editURL = "/_edit%s" % self.page_id, \
                    history = "history", historyURL = self.historyURL, markup = markup.markup)
        else:
            self.redirect("/_edit%s" % self.page_id)
        

class EditPage(Handler):
    def get(self, dont_use_me):
        self.startup(self.request)
        if self.logState == 'login':
            self.redirect('/login/?refURL=/_edit%s' % self.page_id)
        markupText = self.read_from_cache_or_db(self.page_id, self.pageQuery, "first")
        if markupText:
            self.render("edit.html", logState = self.logState, logURL = self.logURL, \
                        editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                        history = "history", markup = markupText.markup)
        else:
            self.render("edit.html", logState = self.logState, logURL = self.logURL, editState = "view", \
                historyURL = self.historyURL, editURL = "%s" % self.page_id)
        

    def post(self, dont_use_me):
        #I should probably factor out all of the common params in some way. e.g. logState and logURL.
        self.startup(self.request)
        markup = self.request.get('markup')
        if not markup:
            self.render("edit.html", logState = self.logState, logURL = self.logURL, \
                         editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                         history = "history", error = "No blank submissions plz!")
        else:
            #need a urlObj so that entry can specify it as its parent. 
            #this gives us strong consistency in datastore reads, so user will always see what he/she just posted.
            urlObj = self.read_from_cache_or_db(self.page_id, self.urlQuery, "first")
            if not urlObj:
                urlObj = URL(url = self.page_id, key_name = self.page_id)
                self.cache_and_db_write(urlObj, {'url_%s' % self.page_id:self.urlQuery})
            dbObj = Entry(parent = urlObj.key(), markup = markup, url = self.page_id, createdBy = self.username)
            cacheDict = {self.page_id:self.pageQuery, "history_%s" % self.page_id:self.pageQuery}
            self.cache_and_db_write(dbObj,cacheDict) 
            self.redirect("%s" % self.page_id)

class HistoryPage(Handler):

    def get(self, dont_use_me):
        self.startup(self.request)
        versions = self.read_from_cache_or_db("history_%s" % self.page_id, self.pageQuery, "all") 
        logging.info("versions is %s" % versions)
        if not versions:
            logging.info("no history found for this page")
            self.render("history.html", logState = self.logState, logURl = self.logURL, \
                        editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                        history = "history", error = "No history for this page yet")
        else:
            logging.info("history found for this page")
            for version in versions:
                #slightly inefficient bc I'm going to iterate through this list once here, and once again on render. 
                #probably doesn't matter since it's such a tiny list? Should I care about this inefficiency?
                if len(version.markup) > 30:
                    version.markup = version.markup[0:40] + "..."
            self.render("history.html", logState = self.logState, logURl = self.logURL, \
                        editState = "view", editURL = "%s" % self.page_id, historyURL = self.historyURL, \
                        history = "history", versions = versions)

class Welcome(Handler):

    def get(self):
        self.startup(self.request)
        self.render("welcome.html", logState = self.logState, logURl = self.logURL)

class Signup(Handler):

    #to dos: finish post function so that it...
    #   - Do database write in a transaction, rather than checking for username existance in one call, and then writing in a second call
    #        This is bad because state of DB could theoretically change between time of those calls.
    #   - validates that the html inputs are correct (email syntax)
    #   - In a perfect world, we'd wait for a response back from the db saying that the write was successful before setting the cookie.

    def render_main(self, email="s", username="s", password="s",verify="s", error=""):
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

        #should do all of this escaping in a template later using autoescape true/false
        if password != verify:
            self.render_main(cgi.escape(email),cgi.escape(username),cgi.escape(password),cgi.escape(verify),"Make sure your passwords match!")
        elif not password or not verify or not username:
            self.render_main(cgi.escape(email),cgi.escape(username),cgi.escape(password),cgi.escape(verify),"Please fill in every field.")
        elif UserDB.get_by_key_name(username):
            self.render_main(cgi.escape(email),cgi.escape(username),cgi.escape(password),cgi.escape(verify),"That username exists.")
        else:
            password = saltyPassword.generate_salted_password(password)
            newUser = UserDB(email = email, username = username, password = password, key_name = username)
            newUser.put()
            self.log_user_in(newUser)
            self.redirect(refURL)

class Login(Handler):

    def render_main(self,username="s", password="s", error=""):
        kwargs = {"username":username,"password":password, "error":error}
        self.render("login.html", **kwargs)

    def get(self):
        self.render_main()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        if not username or not password:
            error = "invalid username/password combination - 0"
            #should do this escaping in template. 
            self.render_main(cgi.escape(username), cgi.escape(password), cgi.escape(error))
            return 

        user_entity = UserDB.get_by_key_name(username)
        if user_entity and saltyPassword.is_valid_password(password,user_entity):
            logging.info('valid username and password found')
            self.log_user_in(user_entity)
            refURL = str(self.get_query_param(self.request, 'refURL', '/'))
            logging.info('refURL is %s' % refURL)
            self.redirect(refURL)   

        else:
            error = "invalid username/password combination - 1"
            self.render_main(username,password,error)

class Logout(Handler):

    def get(self):
        refURL = str(self.get_query_param(self.request, 'refURL', '/'))
        self.log_user_out()
        self.redirect(refURL)

class Flush(Handler):

    def get(self):
        self.startup()
        memcache.flush_all()
        self.redirect("/")


PAGE_RE = r'(?:/([a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([ (r"/?", Welcome), (r"/signup/?", Signup), \
                                       (r"/login/?",Login), (r"/logout/?",Logout), \
                                       (r"/flush/?", Flush), ('/_edit' + PAGE_RE, EditPage), \
                                       ('/_history' + PAGE_RE, HistoryPage), (PAGE_RE, WikiPage)], debug=True) 
                                       
def handle_404(request, response, exception):
    response.write("can't find that url")
    response.set_status(404)

def handle_500(request, response, exception):
    response.write("500")
    response.set_status(500)

#application.error_handlers[404] = handle_404
#application.error_handlers[500] = handle_500




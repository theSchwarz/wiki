import hashlib
import sys
import os

#To Do: Use bcrypt instead of hashlib. 
#IMPORTANT: Everything below assumes cookies where format is "readableValue|md5hash". e.g. "3|aslkdfksjdsdf"

#------Below are cookie functions that should be used by all cookies that get set------

serverSecretString = "thisIsMyServerSideSecretAndItsSoooSecure"

def get_usable_cookie_value(appEngineRequestObj, cookieName, defaultValue):
    #returns a programmable cookie value of the same type as the default value. Grabs this value from the user if it's secure,
    #else it creates a new secure cookie from the default value.
    cookieString = get_cookie_string(appEngineRequestObj, cookieName, defaultValue)[0]
    readableValueString = cookieString.split('|')[0]
    print readableValueString
    return type_converter(defaultValue, readableValueString)

def get_cookie_string(appEngineRequestObj, cookieName, defaultValue):
    #checks to see if a cookie value was sent by the user in their request AND if it's secure. Returns a secure value.
    #this is a little ghetto. should change the name to be more clear.

    cookieString = appEngineRequestObj.cookies.get(cookieName,defaultValue)
    if is_valid(cookieString):
        return cookieString, True
    else:
        return make_secure_value(defaultValue), False

def is_valid(cookieValue):
    #expects cookieValue in format "readableValue|md5HashValue"
    readableValue = str(cookieValue).split("|")[0] #str.split returns a list/tuple with N strings delimited by the split character(s)
    if make_secure_value(readableValue) == cookieValue:
        return True
    else:
        return False

def make_secure_value(value,serverSecretString = serverSecretString):
    hashVal = hashlib.md5(str(value)+serverSecretString).hexdigest()
    return "%s|%s" % (value,hashVal)

def type_converter(defaultValue,readableValueString):
    #designed to check default value, and convert cookieString into same type as default value.
    #To do: make a dictionary and support more types.
    if isinstance(defaultValue,int):
        return int(readableValueString)
    if isinstance(defaultValue,float):
        return float(readableValueString)
    else:
        return str(readableValueString)

def set_secure_cookie(appEngineResponseObj, cookieName, value, path):
    secureVal = make_secure_value(value)
    appEngineResponseObj.headers.add_header("Set-Cookie", str("%s = %s; Path=%s" % (cookieName,secureVal,path))) #got burned earlier bc it created unicode and not a string.

def delete_cookie(appEngineRequestObj, appEngineResponseObj, cookieName,path):
    if appEngineRequestObj.cookies.get(cookieName):
        appEngineResponseObj.headers.add_header("Set-Cookie", \
            str("%s =; Path=%s;" % (cookieName,path)))

#----Example implementation-----

"""
pageViewCount = cookies.get_usable_cookie_value(self.request,"pageViewCount",0)
pageViewCount +=1
cookies.set_secure_cookie(self.response, "pageViewCount", pageViewCount)
"""



#------test case------
#note, to use this, you have to take the .cookies part out of get_cookie_string.

"""
def test():
    #make sure to take out ".cookies" from get_cookie_value function to test this
    requestDict = {"pageViews":2}
    print get_cookie_value(requestDict, "pageViews", 0)
    print requestDict
    requestDict = {"pageViews":"2|c81e728d9d4c2f636f067f89cc14862c"}
    print get_cookie_value(requestDict, "pageViews", 0)

test()
"""

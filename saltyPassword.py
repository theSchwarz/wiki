import sys
import os
import hmac
import random
import string

def generate_salt(len_salt):
    return "".join(random.choice(string.letters + string.digits) for x in xrange(len_salt))

def generate_salted_password(pw, salt = ""):
    if not salt:
        salt = generate_salt(16)
    return hmac.new(str(salt),pw).hexdigest()+",%s" % salt

def return_salt(salted_pw):
    return salted_pw.split(",")[1]

def is_valid_password(user_typed_pw,user_entity):
    official_pw = user_entity.password
    pw_salt = return_salt(official_pw)
    salted_user_pw = generate_salted_password(user_typed_pw,pw_salt)
    if salted_user_pw == official_pw:
        return True
    else:
        return False

print return_salt("6e299766397f66e4de19e4e3fd708371,BIFTZaUtFcq4EqJ0")

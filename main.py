#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import cgi
import re
import webapp2


signup_form = """
<h1>Sign-Up Form</h1>

<form method="post" action="/signup">

    <div>Username <input title="Username" type="text" name="username" value="%(username)s"><span style="color: red">%(username_error)s</span></div>
	
    <div>Password <input title="Password" type="password" name="password" value=""><span style="color: red">%(pw_error)s</span></div>
	
    <div>Verify password <input title="Password" type="password" name="verify" value=""><span style="color: red">%(verify_error)s</span></div>
	
    <div>Email (optional) <input title="Email" type="text" name="email" value="%(email)s"><span style="color: red">%(email_error)s</span></div>
	
    <button type="submit">Sign Up!</button>
	
</form>

"""

class Signup(webapp2.RequestHandler):

    def get(self):
        return self.write_form()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        password_verify = self.request.get("verify")
        email = self.request.get("email")

        username_error = ""
        pw_error = ""
        verify_pw_error = ""
        email_error = ""

        have_error = False

        is_username_valid = self.is_username_valid(username=username)
        is_pw_valid = self.is_pw_valid(password=password)
        is_pw_verify_valid = self.is_pw_verify_valid(password=password, password_verify=password_verify)
        is_email_valid = self.is_email_valid(email=email)

        if not is_username_valid:
            username_error = "Not a valid username."
            have_error = True

        if not is_pw_valid:
            pw_error = "Not a valid password."
            have_error = True

        if not is_pw_verify_valid:
            verify_pw_error = "Your passwords don't match."
            have_error = True

        if not is_email_valid:
            email_error = "Not a valid email."
            have_error = True

        if have_error:
            self.write_form(
                username=username,
                email=email,
                username_error=username_error,
                pw_error=pw_error,
                verify_pw_error=verify_pw_error,
                email_error=email_error
            )
        else:
            self.redirect("/welcome?username=" + username)


    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    def is_username_valid(self, username):
        return username and self.USER_RE.match(username)

    PASS_RE = re.compile(r"^.{3,20}$")
    def is_pw_valid(self, password):
        return password and self.PASS_RE.match(password)

    def is_pw_verify_valid(self, password, password_verify):
        return password == password_verify

    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    def is_email_valid(self, email):
        return not email or self.EMAIL_RE.match(email)

    def write_form(self, username="", email="", username_error="", pw_error="", verify_pw_error="", email_error=""):
        self.response.headers['Content-Type'] = 'text/html'
        self.response.out.write(signup_form % {
            "username": username,
            "email": email,
            "username_error": username_error,
            "pw_error": pw_error,
            "verify_error": verify_pw_error,
            "email_error": email_error
        })


class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        return self.response.out.write("<h1>" + "Welcome, " + username + "</h1>")


app = webapp2.WSGIApplication([
	('/', Signup),
    ('/signup', Signup),
    ('/welcome', Welcome)
], debug=True)
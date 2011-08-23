# vim: set ts=2 sw=2
"""
Username/Password Authentication
"""

from django.core.urlresolvers import reverse
from django import forms
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponseRedirect

import logging

import ldap

# some parameters to indicate that status updating is possible
STATUS_UPDATES = False

LOGIN_MESSAGE = "LDAP server"


#def create_user(username, password, name = None):
#  from auth.models import User
#  
#  user = User.get_by_type_and_id('password', username)
#  if user:
#    raise Exception('user exists')
#  
#  info = {'password' : password, 'name': name}
#  user = User.update_or_create(user_type='password', user_id=username, info = info)
#  user.save()

class LoginForm(forms.Form):
  username = forms.CharField(max_length=50)
  password = forms.CharField(widget=forms.PasswordInput(), max_length=100)

def auth_user_ldap(username, password):
  l = ldap.initialize('ldap://%s:%s' % (settings.LDAP_HOST, settings.LDAP_PORT))
  l.protocol_version = ldap.VERSION3
  results = l.search_s(settings.LDAP_BASE,ldap.SCOPE_SUBTREE,'(uid=%s)' % username, ['cn', 'mail', 'uid'])
  if len(results) != 1:
    return False
  user = results[0][1]
  try:
    l.simple_bind_s(results[0][0], password)
  except ldap.LDAPError, e:
    logging.warning(e)
    return False
  else:
    return user

# the view for logging in
def ldap_login_view(request):
  from auth.view_utils import render_template
  from auth.views import after
  from auth.models import User

  error = None
  
  if request.method == "GET":
    form = LoginForm()
  else:
    form = LoginForm(request.POST)

    # set this in case we came here straight from the multi-login chooser
    # and thus did not have a chance to hit the "start/password" URL
    request.session['auth_system_name'] = 'ldap'
    if request.POST.has_key('return_url'):
      request.session['auth_return_url'] = request.POST.get('return_url')

    if form.is_valid():
      username = form.cleaned_data['username'].strip()
      password = form.cleaned_data['password'].strip()
      user = auth_user_ldap(username, password)
      logging.info(user)
      if user:
        request.session['ldap_user'] = user
        return HttpResponseRedirect(reverse(after))
      else:
        error = 'Bad Username or Password'
  return render_template(request, 'password/login', {'form': form, 'error': error})
    
#def password_forgotten_view(request):
#  """
#  forgotten password view and submit.
#  includes return_url
#  """
#  from auth.view_utils import render_template
#  from auth.models import User
#
#  if request.method == "GET":
#    return render_template(request, 'password/forgot', {'return_url': request.GET.get('return_url', '')})
#  else:
#    username = request.POST['username']
#    return_url = request.POST['return_url']
#    
#    try:
#      user = User.get_by_type_and_id('password', username)
#    except User.DoesNotExist:
#      return render_template(request, 'password/forgot', {'return_url': request.GET.get('return_url', ''), 'error': 'no such username'})
#    
#    body = """
#
#This is a password reminder:
#
#Your username: %s
#Your password: %s
#
#--
#%s
#""" % (user.user_id, user.info['password'], settings.SITE_TITLE)
#
#    # FIXME: make this a task
#    send_mail('password reminder', body, settings.SERVER_EMAIL, ["%s <%s>" % (user.info['name'], user.info['email'])], fail_silently=False)
#    
#    return HttpResponseRedirect(return_url)
  
def get_auth_url(request, redirect_url = None):
  return reverse(ldap_login_view)
    
def get_user_info_after_auth(request):
  user = request.session['ldap_user']
  logging.info(repr(user))
  del request.session['ldap_user']
  #user_info = user.info
  user_info = {"email": user["mail"][0],
               "name": user["cn"][0], }
  
  return {'type': 'ldap', 'user_id' : user["uid"][0], 'name': user["cn"][0], 'info': user_info, 'token': None}
    
def update_status(token, message):
  pass
  
def send_message(user_id, user_name, user_info, subject, body):
  email = user_info['email']
  name = user_name or user_info.get('name', email)
  send_mail(subject, body, settings.SERVER_EMAIL, ["%s <%s>" % (name, email)], fail_silently=False)    

from __future__ import unicode_literals
from django.db import models
from django.contrib import messages
import re
import bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')

# Create your models here.
class UserManager(models.Manager):
    def register(self, request, first_name, last_name, email, password, confirm):
        valid = True

        if len(first_name) <2:
            messages.error(request, 'First Name is required')
            valid = False
        elif not NAME_REGEX.match(first_name):
            messages.error(request, 'First name should contain only letters')
            valid = False

        if len(last_name) <2:
            messages.error(request, 'Last Name is required')
            valid = False
        elif not NAME_REGEX.match(last_name):
            messages.error(request, 'Last name should contain only letters')
            valid = False

        if len(email) < 1:
            messages.error(request, 'Email is required')
            valid = False
        elif not EMAIL_REGEX.match(email):
            messages.error(request, 'Email is not valid')
            valid = False

        if len(password) <1:
            messages.error(request, 'Password is required')
            valid = False
        elif len(password) < 8:
            messages.error(request, 'Password should contain no fewer than 8 characters')
            valid = False

        if len(confirm) <1:
            messages.error(request, 'Password confirmation is required')
            valid = False
        elif not confirm == password:
            messages.error(request, 'Password Confirmation does not match the password')
            valid = False

        if valid == True:
            pw = request.POST['password'].encode()
            hashed = bcrypt.hashpw(pw, bcrypt.gensalt())

            newUser = User.objects.create(
            first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'],
            pw_hash = hashed)
            newUser.save()
            request.session['id']=newUser.id
            return valid, newUser

    def login(self, request, **loginData):

        if User.objects.get(email=loginData['email']):
            hashed = bcrypt.hashpw(loginData['password'].encode(),
            User.objects.get(email=loginData['email']).pw_hash.encode())

            if User.objects.get(email=loginData['email']).pw_hash == hashed:
                info = User.objects.get(email=loginData['email'])
                return (True, info)
            else:
                return (False, request, messages.error(request, "Password does not match"))
        else:
            return (False, request, messages.error(request, "Email does not exist"))


class User(models.Model):
      first_name = models.CharField(max_length=45)
      last_name = models.CharField(max_length=45)
      email = models.CharField(max_length=100)
      pw_hash = models.CharField(max_length=255)
      created_at = models.DateTimeField(auto_now_add = True)
      updated_at = models.DateTimeField(auto_now = True)
      objects = UserManager()

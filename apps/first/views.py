from django.shortcuts import render, redirect
from .models import User, UserManager
import bcrypt

# Create your views here.
def index(request):
    try:
        request.session['id']
        context={
            'allUsers': User.objects.all(),
            'users': User.objects.get(id=request.session['id'])
        }
        return render(request, 'first/success.html', context)
    except:
        return render(request, 'first/index.html')

def register(request):
    if request.method == 'POST':
        registration = User.objects.register(request, request.POST['first_name'], request.POST['last_name'], request.POST['email'], request.POST['password'], request.POST['confirm'])

        if registration == False:
            return redirect('/')
        return redirect('/')

def login(request):
    if request.method == 'POST':

        loginData = {
            'email': request.POST['email'],
            'password': request.POST['password'],
        }

        user = User.objects.login(request, **loginData)

        if user[0] == True:
            request.session['name'] = user[1].first_name
            return render(request, 'first/success.html')
        else:
            return redirect('/')
    else:
        return redirect('/')


def logout(request):
    request.session.clear()
    return redirect('/')

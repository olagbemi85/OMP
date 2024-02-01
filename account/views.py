from django.shortcuts import render
from .models import *
from django.views import View
from .forms import *
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login


#import random
from .backends import EmailPhoneUsernameAuthenticationBackend as EoP


@login_required
def profile(request):
    user = request.user
    post = User.objects.get(email=user) # This query object give logged in user profile
    context = {'post' : post}
    return render(request, 'account/profile-detail.html', context)


@login_required
def profile_edit(request):
    user = request.user
    pp = User.objects.get(email=user)
    if request.method == 'POST':
        user_form = UserFormUpdate(request.POST, request.FILES, instance=request.user)

        if user_form.is_valid():
            user_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect('account:edit-profile')
        else:
            messages.error(request, 'fail to save profile')
    else:
       	#try:
            user_form = UserFormUpdate(instance=request.user)
        #except:
            #profile = User.objects.create(user=request.user)
            #user_form = UserFormUpdate(instance=profile)
    return render(request, 'account/update_profile.html', {'user_form': user_form, 'pp':pp })


class Register(View):
	user_form = UserForm()
	def get(self, request, data=None):
		if request.user.is_authenticated:
			return redirect('meterapp:home')
		else:
			messages.success(request, 'Please fill in your data')
			context = {'form': self.user_form}
			return render(request, 'account/register.html', context) 
	
	def post(self, request):
		if request.method == 'POST':
			#user_form = UserForm(data=request.POST)
			user_form = UserForm(request.POST)
			username = request.POST['username']
			first_name = request.POST['first_name']
			last_name = request.POST['last_name']
			email = request.POST['email']
			password = request.POST['password1']
			err = {'form' :user_form}

			context = {
				'username':username, 'email':email, 'first_name':first_name, 'last_name':last_name, 'password1':password,
				}

			#password1 = self.cleaned_data.get("password1")
			#password2 = self.cleaned_data.get("password2")
			#if password1 and password2 and password1 != password2:
				#raise ValidationError("Passwords don't match")
			#return password2    
			if user_form.is_valid():
				if not User.objects.filter(username = username).exists():
					if not User.objects.filter(email = email).exists():
						if len(password) < 8:
							messages.error(request, 'password too short')
							return render(request, 'authentications/forms/register.html', err)
                        
						user = User.objects.create_user(username=username, email=email, first_name=first_name, last_name=last_name)
						#create_user_profile()
						user.save()
						user.set_password(password)
						user.save()
						#save_user_profile()

						messages.success(request, 'Account successfully created')
						return redirect('authentication:userlogin')                         
					messages.error(request, 'e-mail taken')
					return render(request, 'authentications/forms/register.html', err)
				messages.error(request, 'user exist')
				return render(request, 'authentications/forms/register.html', err)
			return render(request, 'authentications/forms/register.html', err)
			#return self.get(request, msg)



class UserLoginView(View):
    form_class = UserLoginForm
    template_name = 'account/login.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('meterapp:application')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = self.form_class
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            user = EoP.authenticate(request, username=cd['email'], password=cd['password'])
            if user is not None:
                login(request, user)
                messages.success(request, 'You have successfully logged in!', 'success')
                return redirect('meterapp:application')
            else:
                messages.error(request, 'Your email or password is incorrect!', 'danger')
        return render(request, self.template_name, {'form': form})
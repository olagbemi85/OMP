from django.urls import path
from .views import *
from django.contrib.auth import views as auth_views


app_name = 'account'


urlpatterns = [
    path('edit-profile/', profile_edit, name='edit-profile'),
    path('', UserLoginView.as_view(), name='userlogin'),
    path('profile/', profile, name='profile'),
    path('register/', Register.as_view(), name='register'),
    path('logout', auth_views.LogoutView.as_view(), name='logout'),

]

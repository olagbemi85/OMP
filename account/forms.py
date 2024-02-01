from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError

from django import forms
from django.forms import ModelForm, widgets
from django.forms.widgets import NumberInput
from .models import *
from django.contrib.auth.forms import UserCreationForm
from phonenumber_field.formfields import PhoneNumberField
from phonenumber_field.widgets import PhoneNumberPrefixWidget
#from location.models  import Country, State
from django_countries.widgets import CountrySelectWidget
#from image_uploader_widget.widgets import ImageUploaderWidget


class UserForm(forms.ModelForm):
    username = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'username', 'type':'text'}))
    first_name = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'first name', 'type':'text'}))
    last_name = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'last name', 'type':'text'}))
    email = forms.EmailField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'email'}))
    password = forms.CharField(required=True, widget=forms.PasswordInput(attrs ={'class':'form-control' ,'placeholder':'password', 'type':'password'}))
    phone_number = PhoneNumberField(required=False, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'phone'}))
    nin_number = forms.IntegerField(required=False, widget=forms.NumberInput(attrs ={'class':'form-control' ,'placeholder':'phone'}))
    class Meta():
        model = User
        fields = ('username','password','email','first_name','last_name','nin_number','phone_number')

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2    


class UserFormUpdate(forms.ModelForm):
    email = forms.EmailField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'email'}))
    username = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'username', 'type':'text'}))
    first_name = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'first name', 'type':'text'}))
    last_name = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'last name', 'type':'text'}))
    #nin_number = forms.IntegerField(required=False, widget=forms.NumberInput(attrs ={'class':'form-control' ,'placeholder':'NIN'}))
    address = forms.CharField(required=True, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'address', 'type':'text'}))
    middle_name = forms.CharField(required=False, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'last name', 'type':'text'}))
    #country = forms.ModelChoiceField(required=False, queryset=Country.objects.all(),  widget=forms.Select(attrs={'class': 'form-control'}))
    country = CountryField(blank_label="(select country)")
    lga = forms.ModelChoiceField(required=False, queryset=State.objects.all(),  widget=forms.Select(attrs={'class': 'form-control'}))
    town_city = forms.CharField(required=False, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'last name', 'type':'text'}))
    phone_number = PhoneNumberField(required=False, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'phone'}))
    date_of_birth = forms.DateField(required=False, widget=NumberInput(attrs={'type': 'date', 'class':'form-control'}))
    profile_pic = forms.ImageField(required=False,
        widget = forms.FileInput(
            attrs = {"id" : "imgInp" , # you can access your image field with this id for css styling . 
                'style' : "max-height: 100px ; max-width : 100px ; ", # add style from here .
                "accept":"image/*", "type":"file"}))
    
    password = ReadOnlyPasswordHashField()

    class Meta():
        model = User
        fields = ['username','first_name','last_name','middle_name', 'profile_pic','date_of_birth','phone_number','address','country','town_city','nin_number']
        widgets = {"country": CountrySelectWidget()}               


class UserLoginForm(forms.Form):
    email = forms.CharField(max_length=50, widget=forms.TextInput(attrs ={'class':'form-control' ,'placeholder':'email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control' ,'placeholder':'password', 'type':'password'}))



class CustomUserChangeForm(forms.ModelForm):
    """A form for updating users. Include the fields on
    the user, but replaces the password field with admin's
    disabled password hash display field.
    """
    password = ReadOnlyPasswordHashField()

    class Meta:
        #model = CustomUser
        fields = ('email', 'password', 'is_superuser')
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.urls import reverse
from phonenumber_field.modelfields import PhoneNumberField
from django_countries.fields import CountryField
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy 

def nin_validate_length(value):
    an_integer = value
    a_string = str(an_integer)
    length = len(a_string)
    if length > 11:
        raise ValidationError(
            gettext_lazy('%(value)s is above 11 digits')
        )
    if length < 11:
        raise ValidationError(
            gettext_lazy('%(value)s is below 11 digits')
        )


phone_validator = RegexValidator(r"^(\+?\d{0,4})?\s?-?\s?(\(?\d{3}\)?)\s?-?\s?(\(?\d{3}\)?)\s?-?\s?(\(?\d{4}\)?)?$", "The phone number provided is invalid")

class UserAccountManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        user.set_password(password)
        user.save()

        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model( email=email, is_superuser= True, is_staff= True, is_active=True, **extra_fields)

        user.set_password(password)
        user.save()

        return user

class User(AbstractBaseUser, PermissionsMixin):
    
    is_customer = models.BooleanField(default=True)
    username = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    middle_name = models.CharField(max_length=150, blank=True)
    country = CountryField()
    phone_number = models.CharField(max_length= 16, validators=[phone_validator], unique=True)
    nin_number = models.IntegerField (validators=[nin_validate_length], unique=True)
    postcode = models.CharField(max_length=12, blank=True)
    address_line_1 = models.CharField(max_length=150, blank=True)
    town_city = models.CharField(max_length=150, blank=True, null=True)
    date_of_birth = models.DateField(null=True)
    profile_pic = models.ImageField(upload_to='media/userprofile/', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserAccountManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['email','first_name', 'last_name','nin_number']

    def get_full_name(self):
        return self.first_name

    def get_short_name(self):
        return self.first_name
    
    def __str__(self):
        return self.email


class Notification(models.Model):
    is_read = models.BooleanField(default=False)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    
class State(models.Model):
    stateName = models.CharField(max_length=225)

    def __str__(self):
        return self.stateName
    
    
class LGA(models.Model):
    state = models.ForeignKey(State, related_name='local_gov', on_delete=models.CASCADE)
    localGovName = models.CharField(max_length=225) 
    
    def __str__(self):
        return self.localGovName
    



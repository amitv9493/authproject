from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


class UserProfileSerializer(serializers.ModelSerializer):

  class Meta:
    model = User
    fields = ["id", "first_name", "last_name", "username", "email"]



class RegisterSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())]
  )
  password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
  password2 = serializers.CharField(write_only=True, required=True)

  class Meta:
    model = User
    fields = ('username', 'password', 'password2',
         'email', 'first_name', 'last_name')
    extra_kwargs = {
      'first_name': {'required': True},
      'last_name': {'required': True}
    }

  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs

  def create(self, validated_data):
    user = User.objects.create(
      username=validated_data['username'],
      email=validated_data['email'],
      first_name=validated_data['first_name'],
      last_name=validated_data['last_name']
    )
    user.set_password(validated_data['password'])
    user.save()
    return user


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255)
    class Meta:
        model=User
        fields = [ 'username' ,'password']


class ChangePasswordSerializer(serializers.ModelSerializer):
    current_password = serializers.CharField(max_length=55,style={'input_type':'password'}, write_only=True)
    password = serializers.CharField(max_length=55,style={'input_type':'password'},validators=[validate_password], write_only=True)
    password2 = serializers.CharField(max_length=55,style={'input_type':'password'}, write_only=True)

    class Meta:
        model = User
        fields =['current_password','password','password2']

    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        user = self.context.get('user')
        success= user.check_password(attrs['current_password'])

        if password == password2 and success:
            user.set_password(password)
            user.save()
            return attrs
        raise serializers.ValidationError("password do not match")



"""See imported modules carefully for resetview"""
from .import utils
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError 
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class PasswordResetSerializer(serializers.Serializer):
    email_id = serializers.EmailField()
    class Meta:
        fields = ['email_id']

    def validate(self, attrs):
        email = attrs['email_id']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print(uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print(token)
            link = 'http://localhost:8000/api/user/resetpassword/'+uid+'/'+token
            print(link)
            # send email 
            data={
                'subject':"Reset Your Password",
                'body': "Click on the below link to reset your password \n" + link,
                'to_email': [user.email]
            }
            utils.send_email(data)  # type: ignore 
            return attrs
        raise serializers.ValidationError("This email is not registered!")


class ResetPasswordSerializer(serializers.Serializer):

    password = serializers.CharField(max_length=55,style={'input_type':'password'},validators=[validate_password], write_only=True)
    password2 = serializers.CharField(max_length=55,style={'input_type':'password'}, write_only=True)

    class Meta:
        fields =['password','password2']

    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        uid = self.context.get('uid')
        token = self.context.get('token')
        print(token)
        id = smart_str(urlsafe_base64_decode(uid)) # type: ignore
        user = User.objects.get(id=id)
        
        # try:
        #     if not PasswordResetTokenGenerator().check_token(user, token):
        #         raise serializers.ValidationError("Link is expired or already used!")

        #     if password == password2:
        #         user.set_password(password)
        #         user.save()
        #         return attrs
        #     raise serializers.ValidationError("password do not match")

        # except DjangoUnicodeDecodeError as indentifier:
        #     PasswordResetTokenGenerator().check_token(user,token)
        try:

            if PasswordResetTokenGenerator().check_token(user, token):
                print("token is correct")
                if password == password2:
                    user.set_password(password)
                    user.save()
                    return attrs
                raise serializers.ValidationError("password do not match")

            raise serializers.ValidationError("Link is expired or already used!")
                
        except DjangoUnicodeDecodeError as indentifier:
                PasswordResetTokenGenerator().check_token(user,token)
                raise serializers.ValidationError("Token is not valid or expired.")

            
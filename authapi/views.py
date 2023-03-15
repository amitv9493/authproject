from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import ChangePasswordSerializer, LoginSerializer, PasswordResetSerializer, RegisterSerializer, ResetPasswordSerializer, UserProfileSerializer
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .renderers import UserRenderes
# Create your views here.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegistrationView(APIView):
    renderer_classes = [UserRenderes]
    def post(self,request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            return Response({"msg": "Registration successful"}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    
    def post(self,request, format =None ):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            # email = serializer.data.get('email')
            username= serializer.data.get('username')
            password= serializer.data.get('password')
            user =authenticate(username=username, password=password)

            if user is not None:
                token= get_tokens_for_user(user)
                return Response({"token":token,"msg":"login Successful"}, status=status.HTTP_200_OK)

            return Response({"errors":{"Non_field_errors":["email or password is not valid"]}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

class ProfileView(APIView):
    renderer_classes =[UserRenderes]
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]
    def get(self, request, format=None ):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    renderer_classes =[UserRenderes]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(data=request.data, context={"user":request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg":"Password changed"})
        
        return Response(serializer.errors)



class SendPasswordResetView(APIView):
    renderer_classes = [UserRenderes]
    def post(self, request, format=None):
        # try:
            serializer = PasswordResetSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                return Response({'msg':"Password reset link is sent if it is registered"}, status=status.HTTP_200_OK)
        # except AssertionError:
        #     return Response({"error":"Not a valid data"})

class PasswordResetView(APIView):
    renderer_classes = [UserRenderes]
    def post(self, request, uid, token, format=None):
        serializer = ResetPasswordSerializer(data=request.data, context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg":'password reset successfully'}, status=status.HTTP_200_OK)

from django.urls import path
from .views import LoginView, RegistrationView, ProfileView, ChangePasswordView, SendPasswordResetView,PasswordResetView
urlpatterns = [
    path("registration/",RegistrationView.as_view(), name="registration"),
    path("login/", LoginView.as_view(), name='loginview'),
    path('profile/', ProfileView.as_view(), name='profileview'),
    path('changepassword/', ChangePasswordView.as_view(), name='change-password'),
    path('resetpassword/', SendPasswordResetView.as_view(), name='reset-password'),
    path('resetpassword/<uid>/<token>/', PasswordResetView.as_view(), name="reset-with-link")
    

]

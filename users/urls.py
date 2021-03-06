# urlpatterns = [
# path(^password/reset/', PasswordResetView.as_view(),
#     name='rest_password_reset'),
# path('password/reset/confirm/', PasswordResetConfirmView.as_view(),
#     name='rest_password_reset_confirm'),
# path('login/', LoginView.as_view(), name='rest_login'),
#
# # URLs that require a user to be logged in with a valid session / token.
# path('logout/', LogoutView.as_view(), name='rest_logout'),
# path('user/', UserDetailsView.as_view(), name='rest_user_details'),
# path('password/change/', PasswordChangeView.as_view(), name='rest_password_change'),
# ]
from django.urls import path
from users import views
from .views import login_view, refresh_token_view, logout_view, \
    users_view, get_security_questions, passwordreset, \
    getsecretquestion, passwordresetcomplete, accountactivate, \
    accountactivaterepeatrequest, userupdate

urlpatterns = [
    # path('', include("django.contrib.auth.urls")),
    # path('', views.users),
    path("<int:pk>/", views.user_detail, name='user-detail'),
    path('login/', login_view, name='login'),
    path('users/', users_view, name='users'),
    path('logout/', logout_view, name='logout'),
    path('refreshtokenview/', refresh_token_view, name='refresh_token_view'),
    path('securityquestions/', get_security_questions, name='securityquestions'),
    path('passwordreset/', passwordreset, name='resetpassword'),
    path('secretquestion/<str:token>/', getsecretquestion, name='secretquestion'),
    path('passwordresetcomplete/', passwordresetcomplete, name='passwordresetcomplete'),
    path('activateaccount/<str:token>/', accountactivate, name='activateaccount'),
    path('repeatactivate/', accountactivaterepeatrequest, name='repeatactivate'),
    path('updateuser/', userupdate, name='updateuser'),
]

from django.urls import path, include, re_path

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


urlpatterns = [
    path('', include("django.contrib.auth.urls"))
]

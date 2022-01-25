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
from .views import login_view

urlpatterns = [
    # path('', include("django.contrib.auth.urls")),
    # path('', views.users),
    path("<int:pk>/", views.user_detail, name='user-detail'),
    path('login/', login_view, name='login'),
]

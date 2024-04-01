from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    # Include health_monitorapp URLs
    path('', include('health_monitorapp.urls')),
    # Other URL patterns for the hmwapp app
]



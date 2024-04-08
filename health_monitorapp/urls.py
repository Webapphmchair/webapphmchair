from django.urls import path, include
from django.contrib import admin
from django.contrib.auth import views as auth_views
from . import views
from .views import forgot_password, reset_password
from .forms import CustomPasswordResetForm
from django.contrib.auth.views import PasswordResetDoneView
from .views import dashboard, user_logout
from django.views.generic import TemplateView


urlpatterns = [
    # URL patterns specific to health_monitorapp views
    path('health-records/', views.health_records_list, name='health_records_list'),
    path('add-health-record/', views.add_health_record, name='add_health_record'),
    path('edit-health-record/<int:pk>/', views.edit_health_record, name='edit_health_record'),
    path('delete-health-record/<int:pk>/', views.delete_health_record, name='delete_health_record'),
    path('search-health-records/', views.search_health_records, name='search_health_records'),
    path('export-health-records/', views.export_health_records, name='export_health_records'),
    path('import-health-records/', views.import_health_records, name='import_health_records'),
    path('admin/', admin.site.urls),
    path('add-comment/<int:health_record_id>/', views.add_comment, name='add_comment'), 
    path('edit-comment/<int:comment_id>/', views.edit_comment, name='edit_comment'),
    path('delete-comment/<int:comment_id>/', views.delete_comment, name='delete_comment'),
    path('health_monitorapp/', include('django.contrib.auth.urls')),  

    path('user-profile/', views.user_profile, name='user_profile'),

    # URL patterns for authentication
    path('user_login/', auth_views.LoginView.as_view(template_name='health_monitorapp/login.html'), name='login'),
    path('user_logout/', auth_views.LogoutView.as_view(template_name='health_monitorapp/logout.html'), name='user_logout'),
    path('signup/', views.signup, name='signup'),
    path('approve-accounts/', views.approve_accounts, name='approve_accounts'),
    path('change-password/', views.change_password, name='change_password'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('password-reset/done/', PasswordResetDoneView.as_view(template_name='health_monitorapp/password_reset_done.html'), name='password_reset_done'),
    path('reset-password/<uidb64>/<token>/', reset_password, name='reset_password'),

    # URL pattern for the dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
]

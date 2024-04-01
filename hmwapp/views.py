# views.py in hmwapp

from django.shortcuts import render

def dashboard(request):
    # Render the dashboard HTML template from health_monitorapp templates directory
    return render(request, 'health_monitorapp/dashboard.html')

def user_login(request):
    # Render the login HTML template from health_monitorapp templates directory
    return render(request, 'health_monitorapp/login.html')

def user_logout(request):
    # Render the logout HTML template from health_monitorapp templates directory
    return render(request, 'health_monitorapp/logout.html')



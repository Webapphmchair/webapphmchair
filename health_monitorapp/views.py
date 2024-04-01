from django.shortcuts import render, redirect, get_object_or_404
from matplotlib import pyplot as plt
import os
import numpy as np
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from .models import HealthRecord
from .forms import HealthRecordForm 

# Password View
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password 

# Reset Password View
from django.contrib.auth import forms
from django.contrib.auth.forms import SetPasswordForm, AuthenticationForm
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
import logging

logger = logging.getLogger(__name__)

# Admin view
from .models import CustomUser  
from .forms import CustomUserCreationForm  
from django.contrib.admin.views.decorators import staff_member_required  

# Signup view
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login, logout

def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Newly created user is not active until approved
            user.is_approved = False 

            user.password = make_password(form.cleaned_data['password1'])

            user.save()
            messages.success(request, 'Your account request has been submitted for approval.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'health_monitorapp/signup.html', {'form': form})

# Login view
def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)  # Pass request and data
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, "You are now logged in as {username}")
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()  # For GET requests, initialize with no data

    return render(request=request,
                  template_name="health_monitorapp/login.html",
                  context={"form": form})

# Logout view
def user_logout(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logout

# Change password view
@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important to keep the user logged in
            messages.success(request, 'Your password was successfully updated!')
            return redirect('user_profile')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'health_monitorapp/change_password.html', {'form': form})

class CustomPasswordResetForm(PasswordResetForm):
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not CustomUser.objects.filter(email__iexact=email, is_active=True).exists():
            raise forms.ValidationError("Sorry, we can't find any user with that email address.")
        return email

# Password view
def forgot_password(request):
    logger.debug("Received %s request for forgot_password view", request.method)
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            logger.debug("Form is valid.")
            email = form.cleaned_data['email']
            logger.debug("Email entered in the form: %s", email)  # Print the email for debugging
            user = User.objects.filter(email=email).first()
            if user:
                logger.debug("User found.")
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_url = f"{request.scheme}://{request.get_host()}/reset-password/{uid}/{token}/"
                subject = 'Reset Your Password'
                message = render_to_string('health_monitorapp/password_reset_email.html', {
                    'user': user,
                    'reset_url': reset_url,
                })
                send_mail(subject, message, 'from@example.com', [email])
                return redirect('password_reset_done')
            else:
                logger.debug("User not found.")
        else:
            logger.debug("Form is not valid: %s", form.errors)
            print(form.errors)  # Print form errors for debugging
    else:
        form = CustomPasswordResetForm()
    return render(request, 'health_monitorapp/forgot_password.html', {'form': form})

# Reset Password view
def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                user = authenticate(username=user.username, password=request.POST['new_password1'])
                if user is not None:
                    login(request, user)
                    return redirect('health_monitorapp/password_reset_complete')
        else:
            form = SetPasswordForm(user)
        return render(request, 'health_monitorapp/reset_password.html', {'form': form})
    else:
        return HttpResponse('Invalid password reset link.')

# Account approval view
@login_required
@staff_member_required
def approve_accounts(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        action = request.POST.get('action')  # 'approve' or 'reject'

        user = CustomUser.objects.get(pk=user_id)
        if action == 'approve':
            user.is_approved = True
            user.is_active = True  # Activate the user account
            user.save()
            messages.success(request, 'Account approved successfully!')
        elif action == 'reject':
            user.delete()  # Reject the user by deleting the account
            messages.success(request, 'Account rejected successfully!')
        # Handle other actions as needed

    pending_accounts = CustomUser.objects.filter(is_approved=False)
    return render(request, 'health_monitorapp/approve_accounts.html', {'pending_accounts': pending_accounts})

# Health record views
@login_required
def health_records_list(request):
    records = HealthRecord.objects.all()
    query = request.GET.get('q')

    if query:
        records = records.filter(user_name__icontains=query)  # Assuming user_name is the field to search for

    # Pagination
    paginator = Paginator(records, 10)  # Show 10 records per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'records': records,
 }
    return render(request, 'health_monitorapp/health_records_list.html', {'page_obj': page_obj})

@login_required
def add_health_record(request):
    if request.method == 'POST':
        form = HealthRecordForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Health record added successfully!')
            return redirect('health_records_list')
        else:
            messages.error(request, 'Error occurred while adding health record. Please check the form.')
    else:
        form = HealthRecordForm()
    return render(request, 'health_monitorapp/add_health_record.html', {'form': form})

@login_required
def edit_health_record(request, pk):
    record = get_object_or_404(HealthRecord, pk=pk)
    if request.method == 'POST':
        form = HealthRecordForm(request.POST, instance=record)
        if form.is_valid():
            updated_record = form.save(commit=False)
            updated_record.save()
            print("Health record updated successfully!")
            messages.success(request, 'Health record updated successfully!')
            return redirect('health_records_list')  # Redirect to health records list upon successful update
        else:
            print("Form is not valid:", form.errors)
            messages.error(request, 'Error occurred while updating health record. Please check the form.')
    else:
        form = HealthRecordForm(instance=record)
    return render(request, 'health_monitorapp/edit_health_record.html', {'form': form, 'record': record})

@login_required
def delete_health_record(request, pk):
    record = get_object_or_404(HealthRecord, pk=pk)
    if request.method == 'POST':
        record.delete()
        messages.success(request, 'Health record deleted successfully!')
        # Redirect to health records list view after successful deletion
        return redirect('health_records_list')
    return render(request, 'health_monitorapp/delete_health_record.html', {'record': record})

@login_required
def search_health_records(request):
    # Placeholder for search functionality
    # Implement your search logic here
    return render(request, 'health_monitorapp/search_health_records.html')

@login_required
def export_health_records(request):
    # Placeholder for export functionality
    # Implement your export logic here
    return render(request, 'health_monitorapp/export_health_records.html')

@login_required
def import_health_records(request):
    # Placeholder for import functionality
    # Implement your import logic here
    return render(request, 'health_monitorapp/import_health_records.html')

@login_required
def user_profile(request):
    user = request.user
    return render(request, 'health_monitorapp/user_profile.html', {'user': user})

# Define the dashboard view

def dashboard(request):
    # Placeholder for dashboard functionality
    # Implement your dashboard logic here
    return render(request, 'health_monitorapp/dashboard.html')

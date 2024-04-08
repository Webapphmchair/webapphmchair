# health_monitorapp/forms.py
from django import forms
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.forms import UserCreationForm 
from .models import HealthRecord, CustomUser, Comment # Add CustomUser import here

# Password Reset  
class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(label='Email', max_length=254)

class HealthRecordForm(forms.ModelForm):
    class Meta:
        model = HealthRecord
        fields = ['user_name', 'pulse_rate', 'heart_rate', 'blood_oxygen_level', 'body_temperature', 'height', 'body_weight']

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['text']  # Remove 'health_record_id' from the fields

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['text'].widget = forms.Textarea(attrs={'class': 'form-control', 'rows': 3})

class EditCommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['text']

# Create a new form for user registration with the approval feature
class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'password1', 'password2', 'user_name')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_active = False  # Set the user as inactive initially
        if commit:
            user.set_password(self.cleaned_data['password1']) 
            user.save()
        return user


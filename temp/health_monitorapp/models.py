from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import AbstractUser

class HealthRecord(models.Model):
    user_name = models.CharField(max_length=100, verbose_name="User Name")
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name="Timestamp")
    pulse_rate = models.FloatField(validators=[MinValueValidator(0)], verbose_name="Pulse Rate (bpm)")
    heart_rate = models.FloatField(validators=[MinValueValidator(0)], verbose_name="Heart Rate (bpm)")
    blood_oxygen_level = models.FloatField(validators=[MinValueValidator(0), MaxValueValidator(100)], verbose_name="Blood Oxygen Level (%)")
    body_temperature = models.FloatField(validators=[MinValueValidator(0)], verbose_name="Body Temperature (°C)")
    height = models.FloatField(validators=[MinValueValidator(0)], blank=True, null=True, verbose_name="Height (cm)")
    body_weight = models.FloatField(validators=[MinValueValidator(0)], blank=True, null=True, verbose_name="Body Weight (kg)")

    class Meta:
        verbose_name = "Health Record"
        verbose_name_plural = "Health Records" 
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user_name} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    def get_bmi(self):
        """Calculate BMI based on weight and height."""
        if self.height is None or self.body_weight is None:
            return None

        height_in_meters = self.height / 100  # Convert height from cm to meters
        bmi = self.body_weight / (height_in_meters ** 2)
        return bmi

    def get_status(self):
        """Returns a simple diagnosis based on recorded parameters."""
        status = []

        if self.pulse_rate < 60:
            status.append("Low pulse rate")
        elif self.pulse_rate > 100:
            status.append("High pulse rate")

        if self.heart_rate < 60:
            status.append("Low heart rate")
        elif self.heart_rate > 100:
            status.append("High heart rate")

        if self.blood_oxygen_level < 90:
            status.append("Low blood oxygen level")

        if self.body_temperature < 36.1:
            status.append("Low body temperature")
        elif self.body_temperature > 37.2:
            status.append("High body temperature")

        bmi = self.get_bmi()
        if bmi is not None:
            if bmi < 18.5:
                status.append("Underweight")
            elif bmi >= 18.5 and bmi < 25:
                status.append("Normal weight")
            elif bmi >= 25 and bmi < 30:
                status.append("Overweight")
            else:
                status.append("Obese")

        return status if status else ["Normal"]

# Add a new field to the CustomUser model to track approval status
class CustomUser(AbstractUser):
    user_name = models.CharField(max_length=100)  # Add the user_name field
    is_approved = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Custom User"
        verbose_name_plural = "Custom Users"

# Add related_name to avoid clash with auth.User
CustomUser._meta.get_field('groups').remote_field.related_name = 'custom_user_groups'
CustomUser._meta.get_field('user_permissions').remote_field.related_name = 'custom_user_permissions'

class Meta:
        permissions = [
            ("view_customuser", "Can view custom user"),
        ]
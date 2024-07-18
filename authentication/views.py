import random
import string
import hashlib
import time
# from django.core.mail import send_mail
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from .serializers import RegisterSerializer, OTPSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import OTP
from django.core.cache import cache
from rest_framework.throttling import AnonRateThrottle
from django.utils import timezone

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                return Response({'message': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
            User.objects.create_user(username=email, email=email)
            return Response({'message': 'Registration successful. Please verify your email.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RequestOTPView(APIView):
    throttle_classes = [AnonRateThrottle]
    def post(self, request):
        email = request.data.get('email')
        if not User.objects.filter(email=email).exists():
            return Response({'message': 'Email not registered'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(email=email)
        otp_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
        
        OTP.objects.create(user=user, otp=otp_hash)
        print(f'OTP for {email}: {otp_code}')
        cache.set(f"otp_request_{email}", time.time(), timeout=60)
        return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            user = User.objects.get(email=email)
            otp_hash = hashlib.sha256(otp.encode()).hexdigest()
            try:
                otp_obj = OTP.objects.filter(user=user).latest('created_at')
            except OTP.DoesNotExist:
                return Response({'message': 'OTP not found. Please request a new OTP.'}, status=status.HTTP_404_NOT_FOUND)
            if otp_obj.verified:
                return Response({'message': 'OTP already verified'}, status=status.HTTP_400_BAD_REQUEST)
            if otp_obj.otp != otp_hash:
                return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            if (timezone.now() - otp_obj.created_at).seconds > 300:
                return Response({'message': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
            otp_obj.verified = True
            otp_obj.save()

            refresh = RefreshToken.for_user(user)
            return Response({'message': 'Login successful', 'token': str(refresh.access_token)}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
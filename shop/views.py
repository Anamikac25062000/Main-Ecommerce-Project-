from django.shortcuts import render,redirect
from .models import Category,Product
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string

# Create your views here.
def home(request):
         category_data=Category.objects.all()
         return render(request,"category.html",{"datas":category_data})
@login_required
def product_detail(request,p):
    category_type=Category.objects.get(slug=p)
    product_data=Product.objects.filter(category__slug=p)
    return  render(request,"product_details.html",{'product_datas':product_data,'category_type':category_type})
@login_required
def products_data(request,p):
    pr=Product.objects.get(slug=p)
    return render(request,"products.html",{'p_data':pr})

def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP for registration is: {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def signup(request):
    if(request.method=="POST"):
            u=request.POST['u']
            p=request.POST['p']
            cp=request.POST['cp']
            e=request.POST['e']
            f=request.POST['f']
            l=request.POST['l']
            if(p==cp):
                u=User.objects.create_user(username=u,
                                           password=p,
                                           email=e,
                                           first_name=f,
                                           last_name=l)
                u.save()
                return redirect('shop:home')
            else:
                messages.error(request,"PASSWORDS ARE NOT SAME")
    return render(request,'signup.html')

def verify_otp(request):
    if request.method == "POST":
        otp_entered = request.POST['otp']
        otp_saved = request.session.get('otp')
        if otp_entered == otp_saved:
            # Save user and clear OTP from session
            u = User(username=request.POST['u'], email=request.POST['e'], first_name=request.POST['f'], last_name=request.POST['l'])
            u.set_password(request.POST['p'])
            u.save()
            del request.session['otp']
            return redirect('shop:home')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
    return render(request, 'verify_otp.html')

def user_login(request):
    if(request.method=="POST"):
        username = request.POST['u']
        password = request.POST['p']
        user=authenticate(username=username,password=password)
        if user:
            login(request,user)
            return redirect('shop:home')
        else:
            messages.error(request,"Invalid User Credentials")

    return render(request,'login.html')

def user_logout(request):
    logout(request)
    return redirect('shop:home')

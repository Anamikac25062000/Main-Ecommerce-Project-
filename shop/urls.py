from django.urls import path
from shop import views
app_name="shop"


urlpatterns=[
    path("",views.home,name="home"),
    path("allproducts/<slug:p>",views.product_detail,name="product_detail"),
    path("productdata/<slug:p>",views.products_data,name="products"),
    path('signup/',views.signup,name="signup"),
    path("login/",views.user_login,name="user_login"),
    path("logout/",views.user_logout,name="user_logout")

]
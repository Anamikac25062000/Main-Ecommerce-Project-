from django.shortcuts import render,redirect
from shop.models import Product
from .models import Cart,Account,Order
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required
def cartview(request):
    total=0
    user=request.user
    try:
       product_detail=Cart.objects.filter(user=user)
       for i in product_detail:
           total+=i.quantity*i.products.price
    except CartDoesNotExist:
        Pass

    return render(request,"cart.html",{"product_details":product_detail,"total":total})
@login_required
def add_cart(request,p):
    product=Product.objects.get(id=p)
    user=request.user
    try:
        cart=Cart.objects.get(products=product,user=user)
        if cart.quantity<cart.products.stock:
            cart.quantity+=1
            cart.save()
    except Cart.DoesNotExist:
        cart=Cart.objects.create(user=user,products=product,quantity=1)
        cart.save()
    return redirect('cart:cartview')



@login_required
def cart_item_less(request,id):
    selected_item=Product.objects.get(id=id)
    user=request.user
    try:
        cart_item=Cart.objects.get(products=selected_item,user=user)
        if cart_item.quantity>1:
            cart_item.quantity-=1
            cart_item.save()
        else:
            cart_item.delete()
    except Cart.DoesNotExist:
        pass
    return redirect('cart:cartview')
@login_required
def cart_remove(request,id):
    selected_item=Product.objects.get(id=id)
    user=request.user
    try:
        cart_item=Cart.objects.get(products=selected_item,user=user)
        cart_item.delete()
    except:
        pass
    return redirect('cart:cartview')


@login_required
def orderform(request):
    total=0
    if(request.method=="POST"):
        a=request.POST['a']
        p=request.POST['p']
        ac=request.POST['ac']
        user=request.user
        cart=Cart.objects.filter(user=user)
        for i in cart:
            total+=i.quantity*i.products.price
        n=Account.objects.get(account_no=ac)
        if(n.amount>=total):
            n.amount=n.amount-total
            n.save()
            for i in cart:
                o=Order.objects.create(user=user,products=i.products,address=a,phone=p,order_status="Paid",noofitems=i.quantity)
                i.products.stock=i.products.stock-i.quantity
                i.products.save()
                o.save()
            cart.delete()
            msg="Order placed successfully"
            return render(request,"orderdetail.html",{'msg':msg,'total':total})
        else:
            msg="Insufficient Amount.You can't place order."
            return render(request,"orderdetail.html",{'msg':msg})
    return render(request,"orderform.html")

@login_required
def orderview(request):
    u=request.user
    o=Order.objects.filter(user=u,order_status="Paid")

    return render(request,"orderview.html",{'o':o,'name':u.username})
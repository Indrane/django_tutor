from django.urls import path
from . import views

urlpatterns = [
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    
    # User Dashboard and Profile
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    
    # Post CRUD Operations
    path('create/', views.create_post, name='create_post'),
    path('edit/<int:post_id>/', views.edit_post, name='edit_post'),
    path('delete/<int:post_id>/', views.delete_post, name='delete_post'),
    path('my-posts/', views.my_posts_view, name='my_posts'),
    # path('view/<slug:slug>/', views.view_post, name='view_post'),
    path('<slug:slug>/', views.view_post, name='post_detail'),  # Shorter URL for posts
    
    # Admin Dashboard URLs
    path('admin-dashboard/', views.admin_dashboard_view, name='admin_dashboard'),
    path('admin-users/', views.admin_users_view, name='admin_users'),
    path('admin-posts/', views.admin_posts_view, name='admin_posts'),
]
"""
API URLs for Posts app - Pure DRF Backend
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router for ViewSets
router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'posts', views.PostViewSet, basename='post')

urlpatterns = [
    # Authentication endpoints
    path('auth/login/', views.login_api, name='login_api'),
    path('auth/signup/', views.signup_api, name='signup_api'),
    path('auth/logout/', views.logout_api, name='logout_api'),
    path('auth/me/', views.current_user_api, name='current_user_api'),
    path('auth/change-password/', views.change_password_api, name='change_password_api'),
    
    # Dashboard and stats
    path('dashboard/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
    path('categories/', views.categories_api, name='categories_api'),
    
    # Router URLs (ViewSets)
    path('', include(router.urls)),
]
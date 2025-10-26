"""
URL configuration for blog project - DRF Backend API
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from . import views

# Swagger/OpenAPI schema configuration
schema_view = get_schema_view(
    openapi.Info(
        title="BlogSphere API",
        default_version='v1',
        description="A comprehensive blog API built with Django REST Framework",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="contact@blogsphere.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Django Admin
    path('admin-django/', admin.site.urls),
    
    # API Documentation (Swagger UI)
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    
    # Main API endpoints
    path('api/', include('posts.urls')),
    
    # Root endpoints (for backward compatibility)
    path('', views.index, name='index'),
    path('about/', views.about_us, name='about_us'),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

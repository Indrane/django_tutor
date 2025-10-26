"""
Main blog views - converted to API responses
"""
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from posts.models import Post
from posts.serializers import PostListSerializer
from django.db.models import Q


@api_view(['GET'])
@permission_classes([AllowAny])
def index(request):
    """
    Main blog homepage API - returns published posts with filtering
    """
    # Get filter parameters
    category_filter = request.GET.get('category', 'all')
    search_query = request.GET.get('search', '')
    sort_by = request.GET.get('sort', 'newest')
    
    # Base queryset - only published posts
    posts = Post.objects.filter(status='published')
    
    # Apply category filter
    if category_filter and category_filter != 'all':
        posts = posts.filter(category__iexact=category_filter)
    
    # Apply search filter
    if search_query:
        posts = posts.filter(
            Q(title__icontains=search_query) |
            Q(content__icontains=search_query) |
            Q(author__first_name__icontains=search_query) |
            Q(author__last_name__icontains=search_query)
        )
    
    # Apply sorting
    if sort_by == 'newest':
        posts = posts.order_by('-created_at')
    elif sort_by == 'oldest':
        posts = posts.order_by('created_at')
    elif sort_by == 'most_viewed':
        posts = posts.order_by('-views')
    elif sort_by == 'title':
        posts = posts.order_by('title')
    
    # Get all unique categories for the filter
    all_categories = Post.objects.filter(status='published').values_list('category', flat=True).distinct()
    categories = [cat for cat in all_categories if cat]  # Remove empty categories
    
    # Get featured posts (most viewed)
    featured_posts = Post.objects.filter(status='published').order_by('-views')[:3]
    
    # Pagination (limit to 20 posts)
    posts = posts[:20]
    
    return Response({
        'success': True,
        'message': 'Welcome to BlogSphere API',
        'data': {
            'posts': PostListSerializer(posts, many=True).data,
            'categories': sorted(categories),
            'featured_posts': PostListSerializer(featured_posts, many=True).data,
            'filters': {
                'current_category': category_filter,
                'search_query': search_query,
                'sort_by': sort_by,
            },
            'stats': {
                'total_posts': posts.count(),
                'total_categories': len(categories),
            }
        }
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def about_us(request):
    """
    About us API endpoint
    """
    return Response({
        'success': True,
        'message': 'BlogSphere - Your Digital Story Platform',
        'about': {
            'title': 'About BlogSphere',
            'description': 'BlogSphere is a modern, feature-rich blogging platform built with Django REST Framework. It provides a powerful API for creating, managing, and sharing stories with the world.',
            'features': [
                'RESTful API Architecture',
                'Role-based Access Control (RBAC)',
                'Token-based Authentication',
                'Rich Content Management',
                'Advanced Search & Filtering',
                'Real-time Statistics',
                'Responsive Design Support',
                'Comprehensive Admin Panel'
            ],
            'version': '1.0.0',
            'built_with': [
                'Django 5.2.4',
                'Django REST Framework 3.16.1',
                'drf-yasg (Swagger UI)',
                'PostgreSQL/SQLite',
                'Bootstrap 5.3'
            ],
            'api_documentation': {
                'swagger_ui': '/swagger/',
                'redoc': '/redoc/',
                'json_schema': '/swagger.json'
            }
        }
    })


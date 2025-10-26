"""
Django REST Framework API Views for Blog Backend
Pure DRF implementation - Backend only
"""

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination
from rest_framework import filters
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth.hashers import check_password
from django.db.models import Q, Count, Sum
from django.utils import timezone
from django.utils.text import slugify
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.models import User

from .models import Users, Post
from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer,
    PostSerializer, PostCreateSerializer, PostListSerializer,
    LoginSerializer, PasswordChangeSerializer, DashboardStatsSerializer,
    CategoryStatsSerializer
)
import logging

logger = logging.getLogger(__name__)


class CustomPagination(PageNumberPagination):
    """Custom pagination class"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# Helper function to get user from token
def get_user_from_token(request):
    """Get Users object from DRF token"""
    try:
        if hasattr(request, 'user') and request.user.is_authenticated:
            # The Django user username should match our Users model username
            user = Users.objects.get(username=request.user.username)
            return user
    except Users.DoesNotExist:
        pass
    return None


class IsOwnerOrAdminPermission(permissions.BasePermission):
    """Custom permission to allow users to edit their own content or admins to edit anything"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        user = get_user_from_token(request)
        return user is not None
    
    def has_object_permission(self, request, view, obj):
        user = get_user_from_token(request)
        if not user:
            return False
        
        # Admin can do anything
        if user.is_admin():
            return True
        
        # Object owner can edit their own content
        if hasattr(obj, 'author'):
            return obj.author_id == user.id
        elif hasattr(obj, 'id'):  # For user objects
            return obj.id == user.id
        
        return False


class IsAdminPermission(permissions.BasePermission):
    """Custom permission for admin-only access"""
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        user = get_user_from_token(request)
        return user and user.is_admin()


class IsAuthenticatedCustom(permissions.BasePermission):
    """Custom authentication check"""
    
    def has_permission(self, request, view):
        # First check if user is authenticated via DRF
        if not request.user or not request.user.is_authenticated:
            return False
        # Then check if we can find the corresponding Users object
        user = get_user_from_token(request)
        return user is not None


# Authentication Views
@swagger_auto_schema(
    method='post',
    request_body=LoginSerializer,
    responses={
        200: openapi.Response(
            description="Login successful",
            examples={
                "application/json": {
                    "success": True,
                    "message": "Welcome back, Test!",
                    "user": {"id": 1, "username": "testuser", "email": "test@example.com"},
                    "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
                }
            }
        ),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Invalid credentials")
    }
)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_api(request):
    """Login API endpoint"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        try:
            # Find user by username or email
            user = None
            try:
                user = Users.objects.get(username=username)
            except Users.DoesNotExist:
                if '@' in username:
                    try:
                        user = Users.objects.get(email=username)
                    except Users.DoesNotExist:
                        pass
            
            if user and user.check_password(password) and user.is_active:
                # Create or get Django User for token system
                django_user, created = User.objects.get_or_create(
                    username=user.username,
                    defaults={
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    }
                )
                
                # Create token
                token, created = Token.objects.get_or_create(user=django_user)
                
                return Response({
                    'success': True,
                    'message': f'Welcome back, {user.first_name or user.username}!',
                    'user': UserSerializer(user).data,
                    'token': token.key,
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Invalid credentials or account deactivated'
                }, status=status.HTTP_401_UNAUTHORIZED)
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return Response({
                'success': False,
                'message': 'Login failed'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=UserCreateSerializer,
    responses={
        201: openapi.Response(
            description="User created successfully",
            examples={
                "application/json": {
                    "success": True,
                    "message": "Welcome to BlogSphere, Test! Your account has been created successfully.",
                    "user": {"id": 1, "username": "testuser", "email": "test@example.com", "role": "author"}
                }
            }
        ),
        400: openapi.Response(description="Validation errors")
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def signup_api(request):
    """Signup API endpoint"""
    serializer = UserCreateSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = serializer.save()
            return Response({
                'success': True,
                'message': f'Welcome to BlogSphere, {user.first_name}! Your account has been created successfully.',
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"User creation error: {e}")
            return Response({
                'success': False,
                'message': 'Account creation failed'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    responses={
        200: openapi.Response(description="Logout successful"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_api(request):
    """Logout API endpoint"""
    try:
        request.user.auth_token.delete()
        return Response({
            'success': True,
            'message': 'Successfully logged out'
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': 'Logout failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(description="Current user information"),
        401: openapi.Response(description="Authentication required"),
        404: openapi.Response(description="User not found")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user_api(request):
    """Get current user information"""
    user = get_user_from_token(request)
    if user:
        return Response({
            'success': True,
            'user': UserSerializer(user).data
        })
    return Response({
        'success': False,
        'message': 'User not found'
    }, status=status.HTTP_404_NOT_FOUND)


# User ViewSet
class UserViewSet(viewsets.ModelViewSet):
    """ViewSet for managing users (Admin only)"""
    queryset = Users.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminPermission]
    pagination_class = CustomPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['role', 'is_active']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering_fields = ['created_at', 'username', 'email']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get user statistics"""
        return Response({
            'total_users': Users.objects.count(),
            'active_users': Users.objects.filter(is_active=True).count(),
            'authors': Users.objects.filter(role='author').count(),
            'admins': Users.objects.filter(role='admin').count()
        })


# Post ViewSet
class PostViewSet(viewsets.ModelViewSet):
    """ViewSet for managing posts"""
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticatedCustom]
    pagination_class = CustomPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'category', 'is_featured', 'author']
    search_fields = ['title', 'content', 'excerpt', 'tags']
    ordering_fields = ['created_at', 'updated_at', 'published_at', 'views', 'title']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Return queryset based on user role"""
        user = get_user_from_token(self.request)
        if not user:
            return Post.objects.none()
        
        if user.is_admin():
            return Post.objects.all()
        else:
            return Post.objects.filter(author=user)
    
    def get_serializer_class(self):
        if self.action == 'list':
            return PostListSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return PostCreateSerializer
        return PostSerializer
    
    def perform_create(self, serializer):
        """Set author to current user when creating post"""
        user = get_user_from_token(self.request)
        if not user:
            raise permissions.PermissionDenied("Authentication required")
        
        # Generate unique slug
        title = serializer.validated_data['title']
        base_slug = slugify(title)
        slug = base_slug
        counter = 1
        
        while Post.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        serializer.save(author=user, slug=slug)
    
    def get_permissions(self):
        """Set permissions based on action"""
        if self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsOwnerOrAdminPermission]
        else:
            permission_classes = [IsAuthenticatedCustom]
        
        return [permission() for permission in permission_classes]
    
    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Publish a post"""
        post = self.get_object()
        post.status = 'published'
        if not post.published_at:
            post.published_at = timezone.now()
        post.save()
        return Response({'message': f'Post "{post.title}" published successfully'})
    
    @action(detail=True, methods=['post'])
    def unpublish(self, request, pk=None):
        """Unpublish a post"""
        post = self.get_object()
        post.status = 'draft'
        post.save()
        return Response({'message': f'Post "{post.title}" unpublished'})
    
    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        """Archive a post"""
        post = self.get_object()
        post.status = 'archived'
        post.save()
        return Response({'message': f'Post "{post.title}" archived'})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAdminPermission])
    def feature(self, request, pk=None):
        """Feature/unfeature a post (admin only)"""
        post = self.get_object()
        post.is_featured = not post.is_featured
        post.save()
        action = 'featured' if post.is_featured else 'unfeatured'
        return Response({'message': f'Post "{post.title}" {action}'})
    
    @action(detail=False, methods=['get'])
    def my_posts(self, request):
        """Get current user's posts with statistics"""
        user = get_user_from_token(request)
        if not user:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        posts = Post.objects.filter(author=user)
        stats = {
            'total': posts.count(),
            'published': posts.filter(status='published').count(),
            'draft': posts.filter(status='draft').count(),
            'archived': posts.filter(status='archived').count(),
            'total_views': posts.aggregate(Sum('views'))['views__sum'] or 0
        }
        
        # Apply status filter if requested
        status_filter = request.query_params.get('status')
        if status_filter:
            posts = posts.filter(status=status_filter)
        
        page = self.paginate_queryset(posts.order_by('-created_at'))
        if page is not None:
            serializer = PostListSerializer(page, many=True)
            result = self.get_paginated_response(serializer.data)
            result.data['stats'] = stats
            return result
        
        serializer = PostListSerializer(posts.order_by('-created_at'), many=True)
        return Response({
            'results': serializer.data,
            'stats': stats
        })
    
    @action(detail=False, methods=['get'], permission_classes=[AllowAny])
    def published(self, request):
        """Get all published posts (public endpoint)"""
        posts = Post.objects.filter(status='published').order_by('-published_at')
        
        # Apply filters
        category = request.query_params.get('category')
        if category and category != 'all':
            posts = posts.filter(category__iexact=category)
        
        search = request.query_params.get('search')
        if search:
            posts = posts.filter(
                Q(title__icontains=search) |
                Q(content__icontains=search) |
                Q(excerpt__icontains=search)
            )
        
        page = self.paginate_queryset(posts)
        if page is not None:
            serializer = PostListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = PostListSerializer(posts, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'], permission_classes=[AllowAny])
    def view(self, request, pk=None):
        """View a post (increments view count for published posts)"""
        post = self.get_object()
        
        if post.status == 'published':
            post.views = (post.views or 0) + 1
            post.save(update_fields=['views'])
        
        # Get related posts
        related_posts = Post.objects.filter(
            status='published',
            category=post.category
        ).exclude(id=post.id).order_by('-views')[:4]
        
        return Response({
            'post': PostSerializer(post).data,
            'related_posts': PostListSerializer(related_posts, many=True).data
        })


# Stats and Categories
@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(description="Dashboard statistics"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticatedCustom])
def dashboard_stats_api(request):
    """Get dashboard statistics"""
    user = get_user_from_token(request)
    if not user:
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if user.is_admin():
        posts = Post.objects.all()
        stats = {
            'total_posts': Post.objects.count(),
            'published_posts': Post.objects.filter(status='published').count(),
            'draft_posts': Post.objects.filter(status='draft').count(),
            'archived_posts': Post.objects.filter(status='archived').count(),
            'total_views': Post.objects.aggregate(Sum('views'))['views__sum'] or 0,
            'total_users': Users.objects.count(),
            'total_authors': Users.objects.filter(role='author').count(),
            'total_admins': Users.objects.filter(role='admin').count(),
        }
        recent_posts = Post.objects.order_by('-created_at')[:10]
    else:
        posts = Post.objects.filter(author=user)
        stats = {
            'total_posts': posts.count(),
            'published_posts': posts.filter(status='published').count(),
            'draft_posts': posts.filter(status='draft').count(),
            'archived_posts': posts.filter(status='archived').count(),
            'total_views': posts.aggregate(Sum('views'))['views__sum'] or 0,
        }
        recent_posts = posts.order_by('-created_at')[:10]
    
    stats['recent_posts'] = PostListSerializer(recent_posts, many=True).data
    return Response(stats)


@api_view(['GET'])
@permission_classes([AllowAny])
def categories_api(request):
    """Get all categories with post counts"""
    categories = Post.objects.filter(status='published').values('category').annotate(
        count=Count('category')
    ).order_by('-count')
    
    return Response([
        {'category': cat['category'], 'count': cat['count']} 
        for cat in categories if cat['category']
    ])

    
@swagger_auto_schema(
    method='post',
    request_body=PasswordChangeSerializer,
    responses={
        200: openapi.Response(description="Password changed successfully"),
        400: openapi.Response(description="Invalid current password or validation errors"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticatedCustom])
def change_password_api(request):
    """Change password API endpoint"""
    user = get_user_from_token(request)
    if not user:
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    
    serializer = PasswordChangeSerializer(data=request.data)
    if serializer.is_valid():
        current_password = serializer.validated_data['current_password']
        new_password = serializer.validated_data['new_password']
        
        if user.check_password(current_password):
            user.set_password(new_password)
            user.save()
            return Response({
                'success': True,
                'message': 'Password changed successfully'
            })
        else:
            return Response({
                'success': False,
                'message': 'Current password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

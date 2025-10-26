"""
Serializers for the Blog API
"""

from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import Users, Post
import re


class UserSerializer(serializers.ModelSerializer):
    """
    User serializer for API responses (excludes password)
    """
    full_name = serializers.SerializerMethodField()
    role_display = serializers.SerializerMethodField()
    posts_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Users
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'role', 'role_display', 'bio', 'profile_picture', 'website', 
            'location', 'birth_date', 'is_active', 'newsletter_subscription',
            'created_at', 'updated_at', 'posts_count'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    
    def get_role_display(self, obj):
        return obj.get_role_display_name()
    
    def get_posts_count(self, obj):
        return obj.posts.filter(status='published').count()


class UserCreateSerializer(serializers.ModelSerializer):
    """
    User creation serializer with password handling
    """
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = Users
        fields = [
            'username', 'email', 'password', 'confirm_password', 'first_name', 
            'last_name', 'role', 'bio', 'profile_picture', 'website', 'location', 
            'birth_date', 'newsletter_subscription'
        ]
    
    def validate_username(self, value):
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError("Username can only contain letters, numbers, and underscores.")
        if Users.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value
    
    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Invalid email format.")
        if Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value
    
    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number.")
        return value
    
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords don't match."})
        return attrs
    
    def create(self, validated_data):
        from django.contrib.auth.models import User
        from rest_framework.authtoken.models import Token
        
        validated_data.pop('confirm_password')
        password = validated_data['password']
        validated_data['password'] = make_password(password)
        
        # Create the custom Users object
        user = super().create(validated_data)
        
        # Create corresponding Django User for token authentication
        django_user = User.objects.create_user(
            username=user.username,
            email=user.email,
            password=password,  # Use plain password for Django user
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        # Create token for the Django user
        token = Token.objects.create(user=django_user)
        
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    User update serializer (excludes sensitive fields like username/email)
    """
    class Meta:
        model = Users
        fields = [
            'first_name', 'last_name', 'bio', 'profile_picture', 'website', 
            'location', 'birth_date', 'newsletter_subscription'
        ]


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change
    """
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    confirm_password = serializers.CharField(required=True)
    
    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number.")
        return value
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords don't match."})
        return attrs


class PostSerializer(serializers.ModelSerializer):
    """
    Post serializer for API responses
    """
    author = UserSerializer(read_only=True)
    reading_time = serializers.ReadOnlyField()
    is_published = serializers.ReadOnlyField()
    tags_list = serializers.SerializerMethodField()
    author_name = serializers.SerializerMethodField()
    can_edit = serializers.SerializerMethodField()
    can_delete = serializers.SerializerMethodField()
    
    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug', 'author', 'author_name', 'content', 'excerpt',
            'category', 'tags', 'tags_list', 'featured_image', 'status', 
            'is_featured', 'views', 'reading_time', 'is_published',
            'created_at', 'updated_at', 'published_at', 'can_edit', 'can_delete'
        ]
        read_only_fields = ['id', 'author', 'views', 'created_at', 'updated_at', 'published_at']
    
    def get_tags_list(self, obj):
        return obj.get_tags_list()
    
    def get_author_name(self, obj):
        return obj.author.get_full_name() if obj.author else ""
    
    def get_can_edit(self, obj):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            # Convert custom user to match our RBAC system
            user_id = request.session.get('user_id')
            if user_id:
                try:
                    user = Users.objects.get(id=user_id)
                    return obj.can_be_edited_by(user)
                except Users.DoesNotExist:
                    pass
        return False
    
    def get_can_delete(self, obj):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            # Convert custom user to match our RBAC system
            user_id = request.session.get('user_id')
            if user_id:
                try:
                    user = Users.objects.get(id=user_id)
                    return obj.can_be_deleted_by(user)
                except Users.DoesNotExist:
                    pass
        return False


class PostCreateSerializer(serializers.ModelSerializer):
    """
    Post creation/update serializer
    """
    class Meta:
        model = Post
        fields = [
            'title', 'content', 'excerpt', 'category', 'tags', 
            'featured_image', 'status', 'is_featured'
        ]
    
    def validate_title(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Title must be at least 5 characters long.")
        
        # Check for duplicate titles (exclude current instance if updating)
        queryset = Post.objects.filter(title=value.strip())
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        
        if queryset.exists():
            raise serializers.ValidationError("A post with this title already exists.")
        
        return value.strip()
    
    def validate_content(self, value):
        if len(value.strip()) < 50:
            raise serializers.ValidationError("Content must be at least 50 characters long.")
        return value.strip()
    
    def validate_category(self, value):
        if value and value not in dict(Post.CATEGORY_CHOICES):
            raise serializers.ValidationError("Invalid category selected.")
        return value
    
    def validate_status(self, value):
        if value not in dict(Post.STATUS_CHOICES):
            raise serializers.ValidationError("Invalid status selected.")
        return value


class PostListSerializer(serializers.ModelSerializer):
    """
    Lightweight post serializer for list views
    """
    author_name = serializers.SerializerMethodField()
    reading_time = serializers.ReadOnlyField()
    tags_list = serializers.SerializerMethodField()
    
    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug', 'author_name', 'excerpt', 'category', 
            'tags_list', 'featured_image', 'status', 'is_featured', 
            'views', 'reading_time', 'created_at', 'published_at'
        ]
    
    def get_author_name(self, obj):
        return obj.author.get_full_name() if obj.author else ""
    
    def get_tags_list(self, obj):
        return obj.get_tags_list()


class LoginSerializer(serializers.Serializer):
    """
    Login serializer
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    remember_me = serializers.BooleanField(default=False)
    
    def validate_username(self, value):
        if not value.strip():
            raise serializers.ValidationError("Username/email is required.")
        return value.strip()
    
    def validate_password(self, value):
        if not value:
            raise serializers.ValidationError("Password is required.")
        return value


class DashboardStatsSerializer(serializers.Serializer):
    """
    Serializer for dashboard statistics
    """
    total_posts = serializers.IntegerField()
    published_posts = serializers.IntegerField()
    draft_posts = serializers.IntegerField()
    archived_posts = serializers.IntegerField()
    total_views = serializers.IntegerField()
    total_users = serializers.IntegerField(default=0)
    recent_posts = PostListSerializer(many=True)


class CategoryStatsSerializer(serializers.Serializer):
    """
    Serializer for category statistics
    """
    category = serializers.CharField()
    count = serializers.IntegerField()

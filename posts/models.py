from django.db import models
from django.urls import reverse
from django.utils import timezone

# Create your models here.


class Users(models.Model):
    """
    Custom User model for blog application with RBAC (Role-Based Access Control)
    """
    
    # User Role Choices
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('author', 'Author'),
    ]
    
    # Basic user information
    username = models.CharField(max_length=150, unique=True, help_text="Unique username for login")
    email = models.EmailField(unique=True, help_text="User's email address", default="")
    password = models.CharField(max_length=128, help_text="Hashed password")
    first_name = models.CharField(max_length=30, help_text="User's first name", default="")
    last_name = models.CharField(max_length=30, help_text="User's last name", default="")
    
    # RBAC - Role and Permissions
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='author', help_text="User role for access control")
    
    # Profile information
    bio = models.TextField(max_length=500, blank=True, help_text="Tell us about yourself")
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    website = models.URLField(blank=True, help_text="Your website or portfolio URL")
    location = models.CharField(max_length=100, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    
    # User status
    is_active = models.BooleanField(default=True, help_text="Designates whether this user should be treated as active")
    is_staff = models.BooleanField(default=False, help_text="Designates whether the user can log into the admin site")
    
    # Newsletter subscription
    newsletter_subscription = models.BooleanField(default=False, help_text="User opted for newsletter")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.username
    
    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        full_name = f'{self.first_name} {self.last_name}'
        return full_name.strip()
    
    def get_absolute_url(self):
        return reverse('user_profile', kwargs={'pk': self.pk})
    
    def check_password(self, raw_password):
        """Check if the provided password matches the user's password."""
        from django.contrib.auth.hashers import check_password
        return check_password(raw_password, self.password)
    
    def set_password(self, raw_password):
        """Set the user's password with proper hashing."""
        from django.contrib.auth.hashers import make_password
        self.password = make_password(raw_password)
    
    # RBAC Permission Methods
    def is_admin(self):
        """Check if user has admin role."""
        return self.role == 'admin'
    
    def is_author(self):
        """Check if user has author role."""
        return self.role == 'author'
    
    def can_manage_users(self):
        """Check if user can manage other users (admin only)."""
        return self.is_admin()
    
    def can_manage_all_posts(self):
        """Check if user can manage all posts (admin only)."""
        return self.is_admin()
    
    def can_create_post(self):
        """Check if user can create posts (both admin and author)."""
        return self.role in ['admin', 'author']
    
    def can_edit_post(self, post):
        """Check if user can edit a specific post."""
        if self.is_admin():
            return True  # Admin can edit any post
        elif self.is_author():
            return post.author_id == self.id  # Author can only edit their own posts
        return False
    
    def can_delete_post(self, post):
        """Check if user can delete a specific post."""
        if self.is_admin():
            return True  # Admin can delete any post
        elif self.is_author():
            return post.author_id == self.id  # Author can only delete their own posts
        return False
    
    def can_view_post(self, post):
        """Check if user can view a specific post."""
        # All authenticated users can view published posts
        if post.status == 'published':
            return True
        # Only admin or post author can view unpublished posts
        return self.is_admin() or post.author_id == self.id
    
    def can_access_admin_panel(self):
        """Check if user can access admin panel."""
        return self.is_admin()
    
    def get_role_display_name(self):
        """Get human-readable role name."""
        return dict(self.ROLE_CHOICES).get(self.role, 'Unknown')
    
    def save(self, *args, **kwargs):
        """Override save method to set is_staff based on role."""
        # Automatically set is_staff for admin users
        if self.role == 'admin':
            self.is_staff = True
        else:
            self.is_staff = False
        super().save(*args, **kwargs)
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        permissions = [
            ('can_manage_users', 'Can manage all users'),
            ('can_manage_all_posts', 'Can manage all posts'),
            ('can_view_analytics', 'Can view site analytics'),
        ]


class Post(models.Model):
    """
    Blog Post model
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('archived', 'Archived'),
    ]
    
    CATEGORY_CHOICES = [
        ('technology', 'Technology'),
        ('lifestyle', 'Lifestyle'),
        ('travel', 'Travel'),
        ('food', 'Food'),
        ('health', 'Health'),
        ('business', 'Business'),
        ('education', 'Education'),
        ('entertainment', 'Entertainment'),
    ]
    
    title = models.CharField(max_length=200, help_text="Post title")
    slug = models.SlugField(max_length=200, unique=True, help_text="URL-friendly version of title")
    author = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(help_text="Main content of the post")
    excerpt = models.TextField(max_length=300, blank=True, help_text="Brief description of the post")
    
    # SEO and categorization
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, blank=True)
    tags = models.CharField(max_length=200, blank=True, help_text="Comma-separated tags")
    
    # Media
    featured_image = models.ImageField(upload_to='post_images/', blank=True, null=True)
    
    # Publishing
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft')
    is_featured = models.BooleanField(default=False, help_text="Feature this post on homepage")
    views = models.IntegerField(default=0, help_text="Number of views")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)
    
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        """Override save method to set published_at when status changes to published"""
        if self.status == 'published' and not self.published_at:
            self.published_at = timezone.now()
        elif self.status != 'published':
            self.published_at = None
        super().save(*args, **kwargs)
    
    def get_absolute_url(self):
        return reverse('post_detail', kwargs={'slug': self.slug})
    
    def get_tags_list(self):
        """Return tags as a list"""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',')]
        return []
    
    def get_tags(self):
        """Alias for get_tags_list for template compatibility"""
        return self.get_tags_list()
    
    @property
    def reading_time(self):
        """Calculate estimated reading time in minutes"""
        if self.content:
            # Average reading speed is 200-250 words per minute
            word_count = len(self.content.split())
            time_minutes = max(1, round(word_count / 200))
            return time_minutes
        return 1
    
    @property
    def is_published(self):
        """Check if the post is published"""
        return self.status == 'published'
    
    # RBAC Permission Methods for Posts
    def can_be_edited_by(self, user):
        """Check if a specific user can edit this post."""
        return user.can_edit_post(self)
    
    def can_be_deleted_by(self, user):
        """Check if a specific user can delete this post."""
        return user.can_delete_post(self)
    
    def can_be_viewed_by(self, user):
        """Check if a specific user can view this post."""
        return user.can_view_post(self)
    
    def is_owned_by(self, user):
        """Check if this post is owned by the specified user."""
        return self.author_id == user.id
    
    class Meta:
        ordering = ['-published_at', '-created_at']
        permissions = [
            ('can_publish_post', 'Can publish posts'),
            ('can_feature_post', 'Can feature posts'),
            ('can_moderate_post', 'Can moderate posts'),
        ]
    



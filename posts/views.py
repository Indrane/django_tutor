from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import transaction
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.hashers import make_password, check_password
from django.core.paginator import Paginator
from django.http import HttpResponseForbidden
from django.db.models import Count, Sum
from django.utils import timezone
from django.utils.text import slugify
from functools import wraps
from .models import Users, Post
import re

# RBAC Helper Functions
def get_current_user(request):
    """Get current user from session"""
    if 'user_id' not in request.session:
        return None
    try:
        return Users.objects.get(id=request.session['user_id'])
    except Users.DoesNotExist:
        return None

def is_authenticated(request):
    """Check if user is authenticated"""
    return 'user_id' in request.session and get_current_user(request) is not None

def require_login(view_func):
    """Decorator to require user authentication"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not is_authenticated(request):
            messages.error(request, "Please log in to access this page.")
            return redirect('/posts/login/')
        return view_func(request, *args, **kwargs)
    return wrapper

def require_admin(view_func):
    """Decorator to require admin role"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = get_current_user(request)
        if not user:
            messages.error(request, "Please log in to access this page.")
            return redirect('/posts/login/')
        if not user.is_admin():
            messages.error(request, "Access denied. Admin privileges required.")
            return HttpResponseForbidden("Access denied. Admin privileges required.")
        return view_func(request, *args, **kwargs)
    return wrapper

def require_author_or_admin(view_func):
    """Decorator to require author or admin role"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = get_current_user(request)
        if not user:
            messages.error(request, "Please log in to access this page.")
            return redirect('/posts/login/')
        if not (user.is_admin() or user.is_author()):
            messages.error(request, "Access denied. Author or Admin privileges required.")
            return HttpResponseForbidden("Access denied.")
        return view_func(request, *args, **kwargs)
    return wrapper

# Create your views here.
@require_author_or_admin
def create_post(request):
    """View to create a new blog post."""
    current_user = get_current_user(request)
    
    if request.method == 'POST':
        # Extract form data
        title = request.POST.get('title', '').strip()
        content = request.POST.get('content', '').strip()
        excerpt = request.POST.get('excerpt', '').strip()
        category = request.POST.get('category', '')
        tags = request.POST.get('tags', '').strip()
        status = request.POST.get('status', 'draft')
        is_featured = request.POST.get('is_featured') == 'on'
        
        # Handle featured image upload
        featured_image = request.FILES.get('featured_image')
        
        # Validation
        errors = []
        if len(title) < 5:
            errors.append("Title must be at least 5 characters long.")
        if len(content) < 50:
            errors.append("Content must be at least 50 characters long.")
        if category and category not in dict(Post.CATEGORY_CHOICES):
            errors.append("Invalid category selected.")
        if status not in dict(Post.STATUS_CHOICES):
            errors.append("Invalid status selected.")
        
        # Check if title already exists
        if Post.objects.filter(title=title).exists():
            errors.append("A post with this title already exists.")
        
        # Generate slug
        slug = None
        if not errors:
            slug = slugify(title)
            
            # Ensure slug is unique
            original_slug = slug
            counter = 1
            while Post.objects.filter(slug=slug).exists():
                slug = f"{original_slug}-{counter}"
                counter += 1
        
        if errors:
            for error in errors:
                messages.error(request, error)
            context = {
                'current_user': current_user,
                'title': title,
                'content': content,
                'excerpt': excerpt,
                'category': category,
                'tags': tags,
                'status': status,
                'is_featured': is_featured,
            }
            return render(request, 'create_post.html', context)
        
        # Create post
        try:
            with transaction.atomic():
                post = Post.objects.create(
                    title=title,
                    slug=slug,
                    author=current_user,
                    content=content,
                    excerpt=excerpt,
                    category=category,
                    tags=tags,
                    status=status,
                    is_featured=is_featured and current_user.is_admin(),  # Only admins can feature posts
                    featured_image=featured_image
                )
                
                # Set published_at if status is published
                if status == 'published':
                    post.published_at = timezone.now()
                    post.save()
                
                messages.success(request, f"Post '{title}' has been created successfully!")
                
                # Redirect based on user role
                if current_user.is_admin():
                    return redirect('/posts/admin-posts/')
                else:
                    return redirect('/posts/my-posts/')
                    
        except Exception as e:
            messages.error(request, "An error occurred while creating the post.")
            print(f"Post creation error: {e}")
    
    # GET request - show the create form
    context = {
        'current_user': current_user,
        'categories': Post.CATEGORY_CHOICES,
        'status_choices': Post.STATUS_CHOICES,
    }
    return render(request, 'create_post.html', context)

def login_view(request):
    """View for user login with authentication."""
    
    if request.method == 'POST':
        # Extract form data
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        remember_me = request.POST.get('remember_me') == 'on'
        
        # Basic validation
        if not username or not password:
            messages.error(request, "Please enter both username/email and password.")
            return render(request, 'login.html')
        
        # Try to authenticate user
        try:
            user = None
            
            # Try to find user by username first
            try:
                user = Users.objects.get(username=username)
            except Users.DoesNotExist:
                # If username not found, try email
                if '@' in username:
                    try:
                        user = Users.objects.get(email=username)
                    except Users.DoesNotExist:
                        user = None
            
            # Check password if user found
            if user and user.check_password(password):
                if user.is_active:
                    # Store user info in session (simple session-based auth)
                    request.session['user_id'] = user.id
                    request.session['username'] = user.username
                    request.session['user_name'] = user.get_full_name()
                    request.session['user_role'] = user.role  # Store user role for RBAC
                    
                    # Set session expiry based on remember me
                    if not remember_me:
                        request.session.set_expiry(0)  # Browser session only
                    else:
                        request.session.set_expiry(1209600)  # 2 weeks
                    
                    # Success message
                    messages.success(request, f"Welcome back, {user.first_name or user.username}! You have been logged in successfully.")
                    
                    # Role-based redirect after successful login
                    if user.is_admin():
                        # Redirect admin to admin dashboard
                        next_url = request.GET.get('next', '/posts/admin-dashboard/')
                    else:
                        # Redirect regular users (authors) to user dashboard
                        next_url = request.GET.get('next', '/posts/dashboard/')
                    
                    return redirect(next_url)
                else:
                    messages.error(request, "Your account has been deactivated. Please contact support.")
            else:
                messages.error(request, "Invalid username/email or password. Please try again.")
                
        except Exception as e:
            messages.error(request, "An error occurred during login. Please try again.")
            print(f"Login error: {e}")
    
    # GET request or failed POST - show the login form
    return render(request, 'login.html')

def signup_view(request):
    """View for user signup with complete validation and database operations."""
    print("the request is recieved",request)
    if request.method == 'POST':
        # Debug: Print all POST data
        print("POST data:", dict(request.POST))
        print("agree_terms value:", repr(request.POST.get('agree_terms')))
        print("agree_terms in POST:", 'agree_terms' in request.POST)
        
        # Extract form data - Required fields
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        agree_terms = request.POST.get('agree_terms')
        user_role = request.POST.get('role', 'author')  # Default to author role
        
        # Extract optional profile fields
        bio = request.POST.get('bio', '').strip()
        website = request.POST.get('website', '').strip()
        location = request.POST.get('location', '').strip()
        birth_date = request.POST.get('birth_date', '')
        newsletter = request.POST.get('newsletter') == 'on'
        
        # Handle profile picture upload
        profile_picture = request.FILES.get('profile_picture')
        
        # Validation errors list
        errors = []
        
        # Step 1: Input validation for required fields
        if not all([first_name, last_name, username, email, password, confirm_password]):
            errors.append("All required fields must be filled.")
        
        if len(first_name) < 2:
            errors.append("First name must be at least 2 characters long.")
        
        if len(last_name) < 2:
            errors.append("Last name must be at least 2 characters long.")
        
        if len(username) < 3:
            errors.append("Username must be at least 3 characters long.")
        
        # Username validation (letters, numbers, underscores only)
        # indraneel_29
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores.")
        
        # Email validation
        try:
            validate_email(email)
        except ValidationError:
            errors.append("Please enter a valid email address.")
        
        # Password validation
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter.")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter.")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number.")
        
        if password != confirm_password:
            errors.append("Passwords do not match.")
        
        # Check if terms checkbox is checked (can be "on", "1", or just present in POST)
        if not agree_terms or agree_terms not in ['on', '1', 'true']:
            errors.append("You must agree to the Terms of Service.")
        
        print(f"Terms validation - agree_terms: {repr(agree_terms)}, validation passed: {bool(agree_terms and agree_terms in ['on', '1', 'true'])}")
        
        # Validate optional fields
        if website and not website.startswith(('http://', 'https://')):
            website = 'https://' + website  # Auto-add protocol
        
        if bio and len(bio) > 500:
            errors.append("Bio cannot exceed 500 characters.")
        
        if location and len(location) > 100:
            errors.append("Location cannot exceed 100 characters.")
        
        # Validate birth date
        birth_date_obj = None
        if birth_date:
            try:
                from datetime import datetime
                birth_date_obj = datetime.strptime(birth_date, '%Y-%m-%d').date()
                # Check if birth date is not in the future
                from datetime import date
                if birth_date_obj > date.today():
                    errors.append("Birth date cannot be in the future.")
            except ValueError:
                errors.append("Please enter a valid birth date in YYYY-MM-DD format.")
        
        # Validate profile picture
        if profile_picture:
            # Check file size (limit to 5MB)
            if profile_picture.size > 5 * 1024 * 1024:
                errors.append("Profile picture must be smaller than 5MB.")
            
            # Check file type
            allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
            if profile_picture.content_type not in allowed_types:
                errors.append("Profile picture must be a JPEG, PNG, or GIF image.")
        
        # Step 2: Check if user already exists
        if not errors:
            try:
                # Check if username already exists
                if Users.objects.filter(username=username).exists():
                    errors.append("Username already exists. Please choose a different one.")
                
                # Check if email already exists
                if Users.objects.filter(email=email).exists():
                    errors.append("An account with this email already exists.")
                
            except Exception as e:
                errors.append("Database error occurred while checking existing users.")
                print(f"Database check error: {e}")
        
        # If there are validation errors, show them
        if errors:
            for error in errors:
                messages.error(request, error)
            return render(request, 'signup.html')
        
        # Step 3: Create user with transaction (atomic operation)
        try:
            with transaction.atomic():
                # Create the user with all fields
                user = Users.objects.create(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=make_password(password),  # Hash the password
                    role=user_role,  # Set user role
                    bio=bio,
                    website=website,
                    location=location,
                    birth_date=birth_date_obj,
                    profile_picture=profile_picture,
                    is_active=True,  # User can login immediately
                    is_staff=False,
                    newsletter_subscription=newsletter
                )
                
                # Log the successful creation (optional)
                print(f"User created successfully: {username} ({email})")
                print(f"Profile info - Bio: {bool(bio)}, Website: {bool(website)}, Location: {location}")
                
                # Success message
                messages.success(
                    request, 
                    f"🎉 Welcome to BlogSphere, {first_name}! Your account has been created successfully with your profile information. You can now log in and start your blogging journey!"
                )
                
                # Redirect to login page after successful signup
                return redirect('/posts/login/')
                
        except Exception as e:
            # Transaction will automatically rollback on exception
            error_message = "An error occurred while creating your account. Please try again."
            messages.error(request, error_message)
            print(f"User creation error: {e}")
            return render(request, 'signup.html')
    
    # GET request - show the signup form
    return render(request, 'signup.html')

@require_login
def dashboard_view(request):
    """Dashboard view for authenticated users."""
    current_user = get_current_user(request)
    
    # Get user's posts with statistics
    if current_user.is_admin():
        posts = Post.objects.all().order_by('-created_at')
        total_posts = Post.objects.count()
        published_posts = Post.objects.filter(status='published').count()
        draft_posts = Post.objects.filter(status='draft').count()
        archived_posts = Post.objects.filter(status='archived').count()
        total_views = Post.objects.aggregate(total=Sum('views'))['total'] or 0
    else:
        posts = Post.objects.filter(author=current_user).order_by('-created_at')
        total_posts = posts.count()
        published_posts = posts.filter(status='published').count()
        draft_posts = posts.filter(status='draft').count()
        archived_posts = posts.filter(status='archived').count()
        total_views = posts.aggregate(total=Sum('views'))['total'] or 0
    
    context = {
        'current_user': current_user,
        'posts': posts[:20],  # Show latest 20 posts
        'total_posts': total_posts,
        'published_posts': published_posts,
        'draft_posts': draft_posts,
        'archived_posts': archived_posts,
        'total_views': total_views,
    }
    
    # Use different template based on user role
    if current_user.is_admin():
        return render(request, 'admin_dashboard.html', context)
    else:
        return render(request, 'author_dashboard.html', context)

@require_login
def profile_view(request):
    """User profile view with editable information"""
    current_user = get_current_user(request)
    
    if request.method == 'POST':
        # Handle profile update
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        bio = request.POST.get('bio', '').strip()
        website = request.POST.get('website', '').strip()
        location = request.POST.get('location', '').strip()
        birth_date = request.POST.get('birth_date', '')
        
        # Validation
        errors = []
        if len(first_name) < 2:
            errors.append("First name must be at least 2 characters long.")
        if len(last_name) < 2:
            errors.append("Last name must be at least 2 characters long.")
        if bio and len(bio) > 500:
            errors.append("Bio cannot exceed 500 characters.")
        if website and not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        # Validate birth date
        birth_date_obj = None
        if birth_date:
            try:
                from datetime import datetime, date
                birth_date_obj = datetime.strptime(birth_date, '%Y-%m-%d').date()
                if birth_date_obj > date.today():
                    errors.append("Birth date cannot be in the future.")
            except ValueError:
                errors.append("Please enter a valid birth date.")
        
        if errors:
            for error in errors:
                messages.error(request, error)
        else:
            # Update profile
            try:
                current_user.first_name = first_name
                current_user.last_name = last_name
                current_user.bio = bio
                current_user.website = website
                current_user.location = location
                current_user.birth_date = birth_date_obj
                
                # Handle profile picture upload
                if 'profile_picture' in request.FILES:
                    current_user.profile_picture = request.FILES['profile_picture']
                
                current_user.save()
                
                # Update session data
                request.session['user_name'] = current_user.get_full_name()
                
                messages.success(request, "Your profile has been updated successfully!")
            except Exception as e:
                messages.error(request, "An error occurred updating your profile.")
                print(f"Profile update error: {e}")
    
    # Get user's posts stats
    user_posts_count = Post.objects.filter(author=current_user).count()
    user_published_posts = Post.objects.filter(author=current_user, status='published').count()
    user_draft_posts = Post.objects.filter(author=current_user, status='draft').count()
    
    context = {
        'current_user': current_user,
        'user_posts_count': user_posts_count,
        'user_published_posts': user_published_posts,
        'user_draft_posts': user_draft_posts,
    }
    
    return render(request, 'profile.html', context)

def logout_view(request):
    """Logout view to clear session and redirect"""
    # Clear all session data
    request.session.flush()
    
    # Success message
    messages.success(request, "You have been logged out successfully. Come back soon!")
    
    # Redirect to home page
    return redirect('/')

@require_admin
def admin_dashboard_view(request):
    """Admin dashboard with user and post management"""
    current_user = get_current_user(request)
    
    # Get overall statistics
    total_users = Users.objects.count()
    total_posts = Post.objects.count()
    published_posts = Post.objects.filter(status='published').count()
    draft_posts = Post.objects.filter(status='draft').count()
    total_authors = Users.objects.filter(role='author').count()
    total_admins = Users.objects.filter(role='admin').count()
    
    # Get recent users (last 10)
    recent_users = Users.objects.order_by('-created_at')[:10]
    
    # Get recent posts (last 10)
    recent_posts = Post.objects.order_by('-created_at')[:10]
    
    # Get posts needing moderation (drafts or recent posts)
    posts_for_moderation = Post.objects.filter(status='draft').order_by('-created_at')[:5]
    
    # Get category statistics
    category_stats = Post.objects.values('category').annotate(
        count=Count('category')
    ).order_by('-count')[:10]
    
    # Get user activity (users created in last 30 days)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.now() - timedelta(days=30)
    new_users_count = Users.objects.filter(created_at__gte=thirty_days_ago).count()
    new_posts_count = Post.objects.filter(created_at__gte=thirty_days_ago).count()
    
    context = {
        'current_user': current_user,
        'stats': {
            'total_users': total_users,
            'total_posts': total_posts,
            'published_posts': published_posts,
            'draft_posts': draft_posts,
            'total_authors': total_authors,
            'total_admins': total_admins,
            'new_users_count': new_users_count,
            'new_posts_count': new_posts_count,
        },
        'recent_users': recent_users,
        'recent_posts': recent_posts,
        'posts_for_moderation': posts_for_moderation,
        'category_stats': category_stats,
    }
    
    return render(request, 'admin_dashboard.html', context)

@require_admin
def admin_users_view(request):
    """Admin view to manage all users"""
    current_user = get_current_user(request)
    
    # Handle user actions
    if request.method == 'POST':
        action = request.POST.get('action')
        user_id = request.POST.get('user_id')
        
        if action and user_id:
            try:
                target_user = Users.objects.get(id=user_id)
                
                if action == 'activate':
                    target_user.is_active = True
                    target_user.save()
                    messages.success(request, f"User {target_user.username} has been activated.")
                
                elif action == 'deactivate':
                    if target_user.id != current_user.id:  # Prevent self-deactivation
                        target_user.is_active = False
                        target_user.save()
                        messages.success(request, f"User {target_user.username} has been deactivated.")
                    else:
                        messages.error(request, "You cannot deactivate your own account.")
                
                elif action == 'make_admin':
                    target_user.role = 'admin'
                    target_user.save()
                    messages.success(request, f"User {target_user.username} is now an admin.")
                
                elif action == 'make_author':
                    if target_user.id != current_user.id:  # Prevent self-demotion
                        target_user.role = 'author'
                        target_user.save()
                        messages.success(request, f"User {target_user.username} is now an author.")
                    else:
                        messages.error(request, "You cannot change your own role.")
                
            except Users.DoesNotExist:
                messages.error(request, "User not found.")
    
    # Get all users with pagination
    users = Users.objects.order_by('-created_at')
    paginator = Paginator(users, 20)  # 20 users per page
    page_number = request.GET.get('page')
    page_users = paginator.get_page(page_number)
    
    context = {
        'current_user': current_user,
        'users': page_users,
    }
    
    return render(request, 'admin_users.html', context)

@require_admin
def admin_posts_view(request):
    """Admin view to manage all posts"""
    current_user = get_current_user(request)
    
    # Handle post actions
    if request.method == 'POST':
        action = request.POST.get('action')
        post_id = request.POST.get('post_id')
        
        if action and post_id:
            try:
                post = Post.objects.get(id=post_id)
                
                if action == 'publish':
                    post.status = 'published'
                    if not post.published_at:
                        post.published_at = timezone.now()
                    post.save()
                    messages.success(request, f"Post '{post.title}' has been published.")
                
                elif action == 'unpublish':
                    post.status = 'draft'
                    post.save()
                    messages.success(request, f"Post '{post.title}' has been unpublished.")
                
                elif action == 'feature':
                    post.is_featured = True
                    post.save()
                    messages.success(request, f"Post '{post.title}' is now featured.")
                
                elif action == 'unfeature':
                    post.is_featured = False
                    post.save()
                    messages.success(request, f"Post '{post.title}' is no longer featured.")
                
                elif action == 'delete':
                    post_title = post.title
                    post.delete()
                    messages.success(request, f"Post '{post_title}' has been deleted.")
                
            except Post.DoesNotExist:
                messages.error(request, "Post not found.")
    
    # Get all posts with pagination
    posts = Post.objects.order_by('-created_at')
    paginator = Paginator(posts, 15)  # 15 posts per page
    page_number = request.GET.get('page')
    page_posts = paginator.get_page(page_number)
    
    context = {
        'current_user': current_user,
        'posts': page_posts,
    }
    
    return render(request, 'admin_posts.html', context)

@require_author_or_admin
def edit_post(request, post_id):
    """Edit an existing post with RBAC"""
    current_user = get_current_user(request)
    
    try:
        post = Post.objects.get(id=post_id)
        
        # RBAC: Check if user can edit this post
        if not post.can_be_edited_by(current_user):
            messages.error(request, "You don't have permission to edit this post.")
            return HttpResponseForbidden("Access denied.")
        
        if request.method == 'POST':
            # Extract form data
            title = request.POST.get('title', '').strip()
            content = request.POST.get('content', '').strip()
            excerpt = request.POST.get('excerpt', '').strip()
            category = request.POST.get('category', '')
            tags = request.POST.get('tags', '').strip()
            status = request.POST.get('status', 'draft')
            is_featured = request.POST.get('is_featured') == 'on'
            
            # Handle featured image upload
            featured_image = request.FILES.get('featured_image')
            
            # Validation
            errors = []
            if len(title) < 5:
                errors.append("Title must be at least 5 characters long.")
            if len(content) < 50:
                errors.append("Content must be at least 50 characters long.")
            if category and category not in dict(Post.CATEGORY_CHOICES):
                errors.append("Invalid category selected.")
            if status not in dict(Post.STATUS_CHOICES):
                errors.append("Invalid status selected.")
            
            # Check if title already exists (excluding current post)
            if Post.objects.filter(title=title).exclude(id=post.id).exists():
                errors.append("A post with this title already exists.")
            
            # Generate new slug if title changed
            slug = post.slug
            if post.title != title:
                slug = slugify(title)
                original_slug = slug
                counter = 1
                while Post.objects.filter(slug=slug).exclude(id=post.id).exists():
                    slug = f"{original_slug}-{counter}"
                    counter += 1
            
            if errors:
                for error in errors:
                    messages.error(request, error)
                context = {
                    'current_user': current_user,
                    'post': post,
                    'categories': Post.CATEGORY_CHOICES,
                    'status_choices': Post.STATUS_CHOICES,
                }
                return render(request, 'edit_post.html', context)
            
            # Update post
            try:
                with transaction.atomic():
                    post.title = title
                    post.slug = slug
                    post.content = content
                    post.excerpt = excerpt
                    post.category = category
                    post.tags = tags
                    post.status = status
                    
                    # Only admins can change featured status
                    if current_user.is_admin():
                        post.is_featured = is_featured
                    
                    # Handle featured image
                    if featured_image:
                        post.featured_image = featured_image
                    
                    # Set published_at if status changed to published
                    if status == 'published' and not post.published_at:
                        post.published_at = timezone.now()
                    elif status != 'published':
                        post.published_at = None
                    
                    post.save()
                    
                    messages.success(request, f"Post '{title}' has been updated successfully!")
                    
                    # Redirect based on user role
                    if current_user.is_admin():
                        return redirect('/posts/admin-posts/')
                    else:
                        return redirect('/posts/my-posts/')
                        
            except Exception as e:
                messages.error(request, "An error occurred while updating the post.")
                print(f"Post update error: {e}")
        
        # GET request - show the edit form
        context = {
            'current_user': current_user,
            'post': post,
            'categories': Post.CATEGORY_CHOICES,
            'status_choices': Post.STATUS_CHOICES,
        }
        return render(request, 'edit_post.html', context)
        
    except Post.DoesNotExist:
        messages.error(request, "Post not found.")
        return redirect('/posts/dashboard/')

@require_author_or_admin
def delete_post(request, post_id):
    """Delete a post with RBAC"""
    current_user = get_current_user(request)
    
    try:
        post = Post.objects.get(id=post_id)
        
        # RBAC: Check if user can delete this post
        if not post.can_be_deleted_by(current_user):
            messages.error(request, "You don't have permission to delete this post.")
            return HttpResponseForbidden("Access denied.")
        
        post_title = post.title
        post.delete()
        
        messages.success(request, f"Post '{post_title}' has been deleted successfully!")
        
        # Redirect based on user role
        if current_user.is_admin():
            return redirect('/posts/admin-posts/')
        else:
            return redirect('/posts/my-posts/')
            
    except Post.DoesNotExist:
        messages.error(request, "Post not found.")
        return redirect('/posts/dashboard/')

@require_author_or_admin
def my_posts_view(request):
    """View for authors to manage their own posts"""
    current_user = get_current_user(request)
    
    # Get user's posts
    posts = Post.objects.filter(author=current_user).order_by('-created_at')
    
    # Handle post actions (for authors managing their own posts)
    if request.method == 'POST':
        action = request.POST.get('action')
        post_id = request.POST.get('post_id')
        
        if action and post_id:
            try:
                post = Post.objects.get(id=post_id, author=current_user)  # Ensure ownership
                
                if action == 'publish':
                    post.status = 'published'
                    if not post.published_at:
                        post.published_at = timezone.now()
                    post.save()
                    messages.success(request, f"Post '{post.title}' has been published.")
                
                elif action == 'unpublish':
                    post.status = 'draft'
                    post.save()
                    messages.success(request, f"Post '{post.title}' has been unpublished.")
                
                elif action == 'delete':
                    post_title = post.title
                    post.delete()
                    messages.success(request, f"Post '{post_title}' has been deleted.")
                
            except Post.DoesNotExist:
                messages.error(request, "Post not found or you don't have permission to modify it.")
    
    # Get statistics
    total_posts = posts.count()
    published_posts = posts.filter(status='published').count()
    draft_posts = posts.filter(status='draft').count()
    
    # Pagination
    paginator = Paginator(posts, 10)  # 10 posts per page
    page_number = request.GET.get('page')
    page_posts = paginator.get_page(page_number)
    
    context = {
        'current_user': current_user,
        'posts': page_posts,
        'stats': {
            'total_posts': total_posts,
            'published_posts': published_posts,
            'draft_posts': draft_posts,
        }
    }
    
    return render(request, 'my_posts.html', context)

@require_login
def view_post(request, slug):
    """View a single post with RBAC and enhanced features"""
    current_user = get_current_user(request)
    
    try:
        post = Post.objects.get(slug=slug)
        
        # RBAC: Check if user can view this post
        if not post.can_be_viewed_by(current_user):
            messages.error(request, "You don't have permission to view this post.")
            return HttpResponseForbidden("Access denied.")
        
        # Increment views count (only for published posts)
        if post.status == 'published':
            post.views = (post.views or 0) + 1
            post.save(update_fields=['views'])
        
        # Get previous and next posts for navigation
        prev_post = None
        next_post = None
        
        if post.status == 'published':
            # Get previous post (older)
            prev_post = Post.objects.filter(
                status='published',
                published_at__lt=post.published_at
            ).order_by('-published_at').first()
            
            # Get next post (newer)
            next_post = Post.objects.filter(
                status='published',
                published_at__gt=post.published_at
            ).order_by('published_at').first()
        
        # Check if user can edit this post
        user_can_edit = post.can_be_edited_by(current_user)
        
        context = {
            'current_user': current_user,
            'post': post,
            'prev_post': prev_post,
            'next_post': next_post,
            'user_can_edit': user_can_edit,
            'reading_time': post.reading_time,
        }
        
        return render(request, 'view_post.html', context)
        
    except Post.DoesNotExist:
        messages.error(request, "Post not found.")
        return redirect('/posts/dashboard/')
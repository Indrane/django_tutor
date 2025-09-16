from django.http import HttpResponse
from django.shortcuts import render
from posts.models import Post
from django.db.models import Q


# def hello_world(request):
#     """A simple Hello World view using HttpResponse."""
#     return HttpResponse("<strong>Hello, World!</strong>")

# def welcome(request):
#     """A simple Welcome view using HttpResponse."""
#     return HttpResponse("<h1>Welcome to the Blog!</h1>")

def index(request):
    """Main blog homepage with category filtering and all posts."""
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
    
    # Get all unique categories for the filter sidebar
    all_categories = Post.objects.filter(status='published').values_list('category', flat=True).distinct()
    categories = [cat for cat in all_categories if cat]  # Remove empty categories
    
    # Get featured posts (most viewed)
    featured_posts = Post.objects.filter(status='published').order_by('-views')[:3]
    
    context = {
        'posts': posts,
        'categories': sorted(categories),
        'featured_posts': featured_posts,
        'current_category': category_filter,
        'search_query': search_query,
        'sort_by': sort_by,
        'total_posts': posts.count(),
        'name': 'Indraneel'  # Keep original context
    }
    
    return render(request, 'homepage.html', context)

def about_us(request):
    return render(request,'about.html')


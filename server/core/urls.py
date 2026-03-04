"""
URL configuration for Secure Authentication project
"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.db import connection


def health_check(request):
    """Health check endpoint for deployment"""
    try:
        # Test database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        return JsonResponse({
            'status': 'healthy',
            'message': 'Secure Authentication API is running successfully'
        })
    except Exception:
        return JsonResponse({
            'status': 'unhealthy',
        }, status=500)


urlpatterns = [
    path('', health_check, name='health_check'),
    path('health/', health_check, name='health_check_alt'),
    path('admin/', admin.site.urls),
    path('api/auth/', include('users.urls')),
]

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.models import User
import logging
import os

# Security logger setup
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security.log')
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='[%(asctime)s] SECURITY %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
security_logger = logging.getLogger('security')

failed_attempts = {}

def custom_login(request):
    error = ''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')

        if failed_attempts.get(username, 0) >= 5:
            security_logger.warning(f'Account locked: {username} after 5 attempts')
            error = 'Account locked. Try again in 5 minutes.'
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                failed_attempts[username] = 0
                security_logger.info(f'Successful login: {username} from {ip}')
                return redirect('/')
            else:
                failed_attempts[username] = failed_attempts.get(username, 0) + 1
                count = failed_attempts[username]
                security_logger.warning(f'Failed login: {username} - {count} attempts')
                error = 'Invalid username or password.'

    return render(request, 'login.html', {'error': error})

@login_required
def home(request):
    if request.user.is_staff:
        return render(request, 'admin_home.html')
    else:
        return render(request, 'user_home.html')

def custom_logout(request):
    logout(request)
    return redirect('/login/')
import os
import re
import sys
from pathlib import Path

KEYWORDS = [
    (r'(?i)\bpassword\b', 'Password'),
    (r'(?i)\bpasswd\b', 'Password'),
    (r'(?i)\bpwd\b', 'Password',
    (r'(?i)\blogin\b', 'Login',
    (r'(?i)\buser\b', 'Username'),
    (r'(?i)\busername\b', 'Username'),
]

# Функция для фильтрации заведомо ложных срабатываний 
def is_likely_false_positive(line):
    if line.lstrip().startswith(('if', 'elif', 'else')):
        return True
    return False

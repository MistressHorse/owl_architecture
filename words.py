import os
import re
import sys
from pathlib import Path

words = [
    (r'(?i)\bpassword\b', 'Password'),
    (r'(?i)\bpasswd\b', 'Password'),
    (r'(?i)\bpwd\b', 'Password'),
    (r'(?i)\blogin\b', 'Login'),
    (r'(?i)\buser\b', 'Username'),
    (r'(?i)\busername\b', 'Username'),
    (r'(?i)\btoken\b', 'Token'),
    (r'(?i)\baws_key\b', 'AWS_Key'),
    (r'(?i)\baws key\b', 'AWS Key'),
    (r'(?i)\bkey\b', 'Key'),
    (r'(?i)\baws secret\b', 'AWS Secret'),
    (r'(?i)\bsecret\b', 'Secret'),
    (r'(?i)\bemail\b', 'email'),
    (r'(?i)\bip\b', 'ip'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email'),
    (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP'), # IPv4
]

# Функция для фильтрации заведомо ложных срабатываний 
def is_likely_false_positive(line):
    if line.lstrip().startswith(('if', 'elif', 'else', 'import')):
        return True
    return False

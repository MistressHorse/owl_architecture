import os
import re
import sys
from pathlib import Path

words = [
    (r'(?i)\bpassword\b', 'Password', 'medium'),
    (r'(?i)\bpasswd\b', 'Password', 'medium'),
    (r'(?i)\bpwd\b', 'Password', 'medium'),
    (r'(?i)\blogin\b', 'Login', 'low'),
    (r'(?i)\buser\b', 'Username', 'low'),
    (r'(?i)\busername\b', 'Username', 'low'),
    (r'(?i)\btoken\b', 'Token', 'high'),
    (r'(?i)\baws_key\b', 'AWS_Key', 'high'),
    (r'(?i)\baws key\b', 'AWS Key', 'high'),
    (r'(?i)\bkey\b', 'Key', 'high'),
    (r'(?i)\baws secret\b', 'AWS Secret', 'high'),
    (r'(?i)\bsecret\b', 'Secret', 'high'),
    (r'(?i)\bemail\b', 'email', 'low'),
    (r'(?i)\bip\b', 'ip', 'low'),
]

# Функция для фильтрации заведомо ложных срабатываний 
def is_likely_false_positive(line):
    if line.lstrip().startswith(('if', 'elif', 'else', 'import')):
        return True
    return False

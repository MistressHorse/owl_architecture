import re
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

def is_likely_false_positive(line):
    return line.lstrip().startswith(('if', 'elif', 'else', 'import'))

class LeakResult:
    def __init__(self, skip, leak_type=None, severity=None):
        self.skip = skip
        self.leak_type = leak_type
        self.severity = severity

def analyze_line(line):
    line_stripped = line.rstrip('\n')
    if not line_stripped or is_likely_false_positive(line_stripped):
        return LeakResult(skip=True)

    for pattern, leak_type, severity in words:
        if re.search(pattern, line_stripped):
            return LeakResult(skip=False, leak_type=leak_type, severity=severity)

    return LeakResult(skip=True)

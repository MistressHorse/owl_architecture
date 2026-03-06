#Рабочий скан файла по ключевым словам с генерацией отчета.

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
    
def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                line_stripped = line.rstrip('\n')
                if not line_stripped:
                    continue
                if is_likely_false_positive(line_stripped):
                    continue
                for pattern, leak_type, severity in words:
                    if re.search(pattern, line_stripped):
                        findings.append({
                            'file': str(filepath),
                            'line': i,
                            'match': line_stripped,
                            'type': leak_type,
                            'severity': severity
                        })
                        break  
    except Exception:
        pass
    return findings
    
def generate_report(findings, output_file='secrets_report.txt'):
    severity_order = {'high': 3, 'medium': 2, 'low': 1}
    findings.sort(key=lambda x: (-severity_order.get(x['severity'], 0), x['file'], x['line']))

    with open(output_file, 'w', encoding='utf-8') as f:
        current_file = None
        for item in findings:
            if item['file'] != current_file:
                current_file = item['file']
                f.write(f"\n--- {current_file} ---\n")
            f.write(f"  строка {item['line']} [{item['severity']}] {item['type']}\n")
            f.write(f"    {item['match']}\n\n")
    print(f"Отчёт сохранён в {output_file}. Найдено утечек: {len(findings)}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python scanner.py <путь_к_папке_или_файлу>")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isfile(target):
        findings = scan_file(target)
    elif os.path.isdir(target):
        findings = scan_directory(target)
    else:
        print("Указанный путь не существует")
        sys.exit(1)

    generate_report(findings)

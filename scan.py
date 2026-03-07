import sys
from scanner.main import scan

def print_usage():
    print("Использование: python script.py <путь> [режим]")
    print("  режим: medium, agressive (по умолчанию agressive)")
    sys.exit(1)

if len(sys.argv) < 2:
    print_usage()

target = sys.argv[1]
mode = 'agressive'  # по умолчанию
if len(sys.argv) >= 3:
    mode = sys.argv[2]
    if mode not in [ 'medium', 'agressive']:
        print("Неправильный режим. Допустимые:  medium, agressive")
        sys.exit(1)

scan(target, mode)
print(f"Сканирование завершено в режиме {mode}. Проверьте папку audit_json.")


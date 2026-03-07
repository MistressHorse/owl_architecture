from scanner.regex import *
from scanner.entropia import *
from scanner.words import *
import os
import re
import json
import joblib
import math
from collections import Counter

# Загрузка ML модели 
MODEL_PATH = './type_classifier.pkl'
CLASSES_PATH = './type_classes.pkl'
ml_model = None
ml_classes = []
try:
    ml_model = joblib.load(MODEL_PATH)
    ml_classes = joblib.load(CLASSES_PATH)
    print("ML модель загружена. Классы:", ml_classes)
except:
    print("ML модель не найдена, классификация недоступна.")

# Рекомендации 
recommendation= { 
    'token': """
Проблема: Попадание токенов в код (хардкод) или коммиты.
Решение: Немедленно заменить токен и перевыпустить. Используйте переменные окружения, vault-системы (HashiCorp Vault, AWS Secrets Manager). Никогда не храните токены в репозитории.""",
    'phone': """
Проблема: Попадание реальных номеров в тестовые данные, логи, баги.
Решение: Использовать фейковые номера (например, +7 999 999-99-99) в тестах. Хранение: в базе шифровать (AES-256) или хешировать с солью. Не логировать номера в открытом виде.""",
    'email':"""
Проблема: Утечка реальных адресов через код, логи, debug-выводы.
Решение: Проверять код на наличие email-паттернов перед коммитом. Использовать тестовые ящики вида test@example.com.
Хранение: Шифрование в БД, маскирование в логах (например, t***@example.com).""",
    'passport':"""
Проблема: Попадание в код примеров, фикстур, тестовых данных.
Решение: В тестах использовать заведомо невалидные данные (например, 1111 111111). Сканеры можно обучить на регулярные выражения паспортов РФ.
Хранение: Строгое шифрование; доступ только по необходимости; аудит доступа.""",
    'login':"""
Проблема: Хардкод учетных записей в конфигах, особенно для dev-сред.
Решение: Сканеры ищут слова password, pwd и рядом стоящие строки. Используйте dotenv или secret management.
Хранение: Никогда не храните пароли в открытом виде. Используйте bcrypt/argon2 для хеширования.""",
    'password':"""
Проблема: Хардкод учетных записей в конфигах, особенно для dev-сред.
Решение: Сканеры ищут слова password, pwd и рядом стоящие строки. Используйте dotenv или secret management.
Хранение: Никогда не храните пароли в открытом виде. Используйте bcrypt/argon2 для хеширования.""",
    'encrypted':"""
Проблема: Утечка самих зашифрованных данных (например, архив с паролем) или ключей шифрования.
Решение: Ключи шифрования — в Vault, зашифрованные данные — проверять на наличие в репозитории (бинарные файлы).
Хранение: Ключи отдельно от данных; использовать алгоритмы с доказанной стойкостью (AES-256-GCM).""",
    'other_secret':"""
Проблема: Обработка платежных данных в коде без соблюдения PCI DSS.
Решение: Не хранить CVV вообще. Для тестов использовать фейковые номера (например, 4111 1111 1111 1111). Сканеры ищут номера карт (Luhn-алгоритм).
Хранение: Только токенизация через платежного провайдера.""",
    'ip':"""
Проблема: Утечка внутренних IP в логах, конфигах, коде.
Решение: Маскировать IP в логах (например, 192.168.1.xxx), не публиковать внутренние подсети.
Хранение: Агрегировать, анонимизировать (GDPR/152-ФЗ).""",
    'key':"""
Проблема: Приватные ключи в репозитории.
Решение: Сканеры ищут начало блоков (-----BEGIN PRIVATE KEY-----). Добавить .gitignore для файлов с ключами.
Хранение: Используйте агенты (ssh-agent), аппаратные токены (YubiKey) или секретные хранилища.""",
}

# Функция извлечения признаков 
def extract_features(line):
    line = line.strip()
    if not line:
        line = ""
    features = []
    features.append(len(line))
    features.append(entropy(line))
    upper = sum(1 for c in line if c.isupper())
    features.append(upper / max(1, len(line)))
    lower = sum(1 for c in line if c.islower())
    features.append(lower / max(1, len(line)))
    digit = sum(1 for c in line if c.isdigit())
    features.append(digit / max(1, len(line)))
    special = len(line) - upper - lower - digit
    features.append(special / max(1, len(line)))
    features.append(len(set(line)))
    features.append(1 if line and line[0] in '\'"' and line[-1] in '\'"' else 0)
    features.append(1 if '=' in line else 0)
    features.append(1 if ':' in line else 0)
    features.append(1 if line.lstrip().startswith(('#', '//')) else 0)
    features.append(1 if re.search(r'\bpassword\b', line.lower()) else 0)
    features.append(1 if re.search(r'\btoken\b', line.lower()) else 0)
    features.append(1 if re.search(r'\bkey\b', line.lower()) else 0)
    features.append(1 if re.search(r'\bsecret\b', line.lower()) else 0)
    features.append(1 if re.search(r'\b(login|user|username)\b', line.lower()) else 0)
    features.append(1 if re.search(r'@.*\.', line) else 0)
    phone_clean = re.sub(r'\D', '', line)
    features.append(1 if re.match(r'^(\+7|8)[0-9]{10}$', phone_clean) else 0)
    features.append(1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) else 0)
    features.append(1 if re.search(r'^\d{4}[\s-]?\d{6}$', line) else 0)
    features.append(1 if re.search(r'^eyJ[\w-]+\.[\w-]+\.[\w-]+', line) else 0)
    features.append(1 if re.search(r'^AKIA', line) else 0)
    features.append(1 if re.search(r'^ghp_', line) else 0)
    features.append(1 if re.search(r'^(sk_live_|sk_test_)', line) else 0)
    features.append(1 if re.search(r'^-----BEGIN', line) else 0)
    features.append(1 if re.search(r'^AIza', line) else 0)
    features.append(1 if len(line) > 20 and re.fullmatch(r'[A-Za-z0-9+/]+=*', line) else 0)
    features.append(1 if len(line) > 20 and re.fullmatch(r'[0-9a-f]+', line.lower()) else 0)
    return features

def classify_entropy_item(item):
    if ml_model is None:
        return item
    line = item.get('line', '')
    if not line:
        return item
    feats = extract_features(line)
    pred = ml_model.predict([feats])[0]
    proba = ml_model.predict_proba([feats])[0]
    confidence = max(proba)
    item['ml_type'] = pred
    item['ml_confidence'] = confidence
    item['advice'] = recommendation.get(pred, 'Нет рекомендации')
    return item


def clear_all_service_json():
    with open('./audit_json/regex_audit.json','w'):
        pass
    with open('./audit_json/entropia_audit.json','w'):
        pass
    with open('./audit_json/keywords_audit.json','w'):
        pass

def path(filename):
    return f'./{filename}'

def logging(filename, num, line, type, imp, ent, method, kwd_point=None):
    par_to_json(filename, num, line, type, imp, ent, f'./audit_json/{method}_audit.json')

def make_key(obj):
    return (obj['filename'], obj['num'])

def par_to_json(filename, num, line, type, imp, ent, json_path):
    finding = {
        "filename": filename,
        "num": num,
        "line": line,
        "type": type,
        "imp": imp,
        "ent": ent
    }
    if os.path.exists(json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    else:
        data = []
    data.append(finding)
    with open(json_path,'w',encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

#precise - entropy+regex, kwd+regex, kwd+regex+entropy
#medium - precise, kwd+entropy
#agressive - medium, regex, entropy
def precise_mode(r_file, k_file, e_file, service=False):
    with open(f'{r_file}', encoding='utf-8') as f:
        r_data = json.load(f)
    with open(f'{k_file}', encoding='utf-8') as f:
        k_data = json.load(f)
    with open(f'{e_file}', encoding='utf-8') as f:
        e_data = json.load(f)
         # ML
    e_data = [classify_entropy_item(item) for item in e_data]
    
    e_dict = {make_key(x): x for x in e_data}
    k_dict = {make_key(x): x for x in k_data}
    seen = set()
    result = []
    for i in r_data:
        key = make_key(i)
        if key in e_dict or key in k_dict:
            if key in e_dict and key not in seen:
                merged = {**i, **e_dict[key]}
                merged['match'] += ['entropy','regex']
                seen.add(key)
            if key in k_dict:
                merged = {**i, **k_dict[key]}
                merged['match'] += ['regex','keywords']
                seen.add(key)
            result.append(merged)
    if service == False:
        with open('./audit_json/precise_audit_result.json', 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    else:
        return result

def medium_mode(r_file, k_file, e_file, service=False):
    with open(f'{r_file}', encoding='utf-8') as f:
        r_data = json.load(f)
    with open(f'{k_file}', encoding='utf-8') as f:
        k_data = json.load(f)
    with open(f'{e_file}', encoding='utf-8') as f:
        e_data = json.load(f)
    # ML
    e_data = [classify_entropy_item(item) for item in e_data]
    
    k_dict = {make_key(x): x for x in k_data}
    precise_list = precise_mode(r_file, k_file, e_file, True)
    result_med = []
    for i in e_data:
        key = make_key(i)
        if key in k_dict:
            merged = {**i, **k_dict[key]}
            merged['match'] += ['keywords','entropy']
            result_med.append(merged)
    result_d = {}
    for i in precise_list + result_med:
        key = make_key(i)
        result_d[key] = i
    result = list(result_d.values())
    if service == False:
        with open('./audit_json/medium_audit_result.json', 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    else:
        return result
    
def agressivee_mode(r_file, k_file, e_file):
    with open(f'{r_file}', encoding='utf-8') as f:
        r_data = json.load(f)
    with open(f'{k_file}', encoding='utf-8') as f:
        k_data = json.load(f)
    with open(f'{e_file}', encoding='utf-8') as f:
        e_data = json.load(f)
    # ML
    e_data = [classify_entropy_item(item) for item in e_data]
    result_d = {}
    seen = set()
    
    for i in r_data:
        key = make_key(i)
        if key not in result_d:
            result_d[key] = i.copy()
            result_d[key]['match'] = []
        result_d[key]['match'].append('regex')

    for i in e_data:
        key = make_key(i)
        if key not in result_d:
            result_d[key] = i.copy()
            result_d[key]['match'] = []
        result_d[key]['match'].append('entropy')

    for i in k_data:
        key = make_key(i)
        if key in result_d:
            result_d[key]['match'].append('keywords')
    
    result = list(result_d.values())
    with open('./audit_json/agressive_audit_result.json', 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    
    

def search_leaks(direct, method):
    for root, dirs, files in os.walk(direct):
        for filename in files:
            path = os.path.join(root,filename)
            with open(path, 'r') as file:
                num = 0
                for line in file:
                    num+=1
                    if method == 'regex':
                        dlp_base = RegexService('./rules.json')
                        dlp_result = dlp_base.check_line(line)
                        if not dlp_result.skip:
                            logging(filename, num, line, dlp_result.log, dlp_result.imp, None, method)
                    if method == 'entropia':
                        dlp_result = calculate_entropy(line)
                        if not dlp_result.skip:
                            logging(filename, num, line, None, None, dlp_result.entropy, method)
                    if method == 'keywords':
                        dlp_result = analyze_line(line)
                        if not dlp_result.skip:
                            logging(filename, num, line, dlp_result.leak_type, dlp_result.severity, None, method, 1)

def scan(direct, mode):
    clear_all_service_json()
    search_leaks(direct, 'regex')
    search_leaks(direct, 'entropia')
    search_leaks(direct, 'keywords')
    r_file = './audit_json/regex_audit.json'
    k_file = './audit_json/keywords_audit.json'
    e_file = './audit_json/entropia_audit.json'
    if mode == 'precise':
        precise_mode(r_file, k_file, e_file)
    if mode == 'medium':
        medium_mode(r_file, k_file, e_file)
    if mode == 'agressive':
        agressivee_mode(r_file, k_file, e_file)

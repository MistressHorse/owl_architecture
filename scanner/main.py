from scanner.regex import *
from scanner.entropia import *
from scanner.words import *
import os
import re
import json

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
                        
if __name__ == '__main__':
    clear_all_service_json()
    direct = str(input('Введите директорию, в которой будет осуществляться поиск: '))
    search_leaks(direct, 'regex')
    search_leaks(direct, 'entropia')
    search_leaks(direct, 'keywords')
    agressivee_mode('./audit_json/regex_audit.json', 
                    './audit_json/keywords_audit.json', 
                    './audit_json/entropia_audit.json')
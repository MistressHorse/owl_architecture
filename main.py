from regex import *
from entropia import *
import os
import re
import json

def logging(filename, num, line, type, imp, ent, method):
    # with open('./audit.log', 'a', encoding='utf-8') as log_file:
    #     if imp != None:
    #         log_file.write(f'{log} Строка: {line}, файл: {filename}. Уровень критичности: {imp}\n\n')
    #     else:
    #         log_file.write(f'Утечка данных! Строка {k}: {line}, файл: {filename}. Энтропия: {ent}\n')
    compilation(filename, num, line, type, imp, ent, f'./{method}_audit.json')

def make_key(obj):
    return (obj['filename'], obj['num'])

def compilation(filename, num, line, type, imp, ent, json_path):
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
    with open('output.json','w',encoding='utf-8') as f:
        f.dump(data, f, indent=4, ensure_ascii=False)

#precise - entropy+regex, kwd+regex, kwd+regex+entropy
#medium - precise, kwd+entropy
#agressive - medium, regex, entropy
def precise_mode(r_file, k_file, e_file):
    with open(f'{r_file}', encoding='utf-8') as f:
        r_data = json.load(f)
    with open(f'{k_file}', encoding='utf-8') as f:
        k_data = json.load(f)
    with open(f'{e_file}', encoding='utf-8') as f:
        e_data = json.load(f)
    
    e_dict = {make_key(x) for x in e_data}
    k_dict = {make_key(x) for x in k_data}
    result = []
    for i in r_data:
        key = make_key(i)
        if key in e_dict or key in k_dict:
            if key in e_dict:
                merged = {**i, **e_dict(key)}
                merged['conf'] = 'HIGH'
            else:
                merged = {**i, **k_dict(key)}
                merged['conf'] = 'HIGH'
            result.append(merged)
    with open('result.json', 'w', encoding='utf-8') as f:
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
                    # if method == 'keywords':
                        #приравнивание dlp_result и т.д.
                        
if __name__ == '__main__':
    direct = str(input('Введите директорию, в которой будет осуществляться поиск: '))
    search_leaks(direct, 'regex')
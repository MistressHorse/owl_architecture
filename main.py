from regex import *
from entropia import *
import os
import re
import json

def logging(k, line, filename, imp, log, ent=None):
    with open('./audit.log', 'a', encoding='utf-8') as log_file:
        if imp != None:
            log_file.write(f'{log} Строка: {line}, файл: {filename}. Уровень критичности: {imp}\n\n')
        else:
            log_file.write(f'Утечка данных! Строка {k}: {line}, файл: {filename}. Энтропия: {ent}\n')

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


def search_leaks(direct, method):
    for root, dirs, files in os.walk(direct):
        for filename in files:
            path = os.path.join(root,filename)
            with open(path, 'r') as file:
                k = 0
                for line in file:
                    k+=1
                    if method == 'regex':
                        dlp_base = RegexService('./rules.json')
                        dlp_result = dlp_base.check_line(line)
                        if not dlp_result.skip:
                            logging(k, line, filename, dlp_result.imp, dlp_result.log)
                    if method == 'entropia':
                        dlp_result = calculate_entropy(line)
                        if not dlp_result.skip:
                            logging(k, line, filename, None, None, dlp_result.entropy)
                        
if __name__ == '__main__':
    direct = str(input('Введите директорию, в которой будет осуществляться поиск: '))
    search_leaks(direct, 'regex')
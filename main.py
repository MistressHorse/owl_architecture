from regex import *
from entropia import *
import os

def logging(k, line, filename, imp, log, ent=None):
    with open('./audit.log', 'a', encoding='utf-8') as log_file:
        if imp != None:
            log_file.write(f'{log} Строка: {line}, файл: {filename}. Уровень критичности: {imp}')
        else:
            log_file.write(f'Утечка данных! Строка {k}: {line}, файл: {filename}. Энтропия: {ent}\n')


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
                        dlp_result = dlp_base.check_line
                        if not dlp_result.skip:
                            logging(line, filename, dlp_result.imp, dlp_result.log)
                    if method == 'entropia':
                        dlp_result = calculate_entropy(line)
                        if not dlp_result.skip:
                            logging(k, line, filename, None, None, dlp_result.entropy)
                        

direct = str(input('Введите директорию, в которой будет осуществляться поиск: '))
search_leaks(direct, 'entropia')
from regex import RegexService, RegexResult
import entropia
import os
import re

def logging(log, imp, line, filename):
    with open('./audit.log', 'a', encoding='utf-8') as log_file:
        log_file.write(log, f'Строка: {line}, файл: {filename}. Уровень критичности: {imp}')


def search_leaks(direct, method):
    for root, dirs, files in os.walk(direct):
        for filename in files:
            path = os.path.join(root,filename)
            with open(path, 'r') as file:
                for line in file:
                    if method == 'regex':
                        dlp_result = RegexService('./rules.json').check_line
                        if not dlp_result.skip:
                            logging(dlp_result.log, dlp_result.imp, line, filename)
                    #if method == 'entropia':
                        #дописать альтернативный способ

direct = str(input('Введите директорию, в которой будет осуществляться поиск: '))
search_leaks(direct, 'regex')
import re
import json

class RegexResult:
    def __init__(self, skip: bool, log=None, imp=None):
        self.skip = skip
        self.log = log
        self.imp = imp

class RegexService:
    def __init__(self, rules_path):
        self.rules = self.__load_rules(rules_path)

    @staticmethod
    def __load_rules(json_path):
        with open(json_path, 'r') as f:
            config = json.load(f)
        return config["rules"]
    
    def check_line(self, line: str):
        for rule in self.rules:
            if re.search(rule["pattern"], line):
                return RegexResult(
                    skip=False,
                    log=rule["log"],
                    imp=rule["importance"]
                )
        return RegexResult(skip=True)
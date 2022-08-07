#!/usr/bin/python3

from _ast import FunctionDef, Expr, Call

import subprocess
import json
import ast
import argparse
import glob
import os

from shlex import split as sh_split

parser = argparse.ArgumentParser()
parser.add_argument('--code', dest='code',
                    help='code to parse')
parser.add_argument('--file', dest='file',
                    help='code to parse')
parser.add_argument('--struct', action='store_true',
                    help='code to parse')
parser.add_argument('--sec', dest='security',
                    help='code to parse')
parser.add_argument('--slscan', action='store_true')
parser.add_argument('--analysis', dest="analysis")
parser.add_argument('--imports', action='store_true')

args = parser.parse_args()


def jsonifySWAs():
    with open("SWA.dat") as f:
        dat = f.read()

    swa = []
    split_dat = dat.split(";")[:-1]
    for e in split_dat:
        swa.append(json.loads(e))


def parser_file(path: str):
    with open(path) as source:
        tree = ast.parse(source.read())

    analyzer = Analyzer()
    analyzer.walk(tree)
    analyzer.report()


def parser(code: str):
    tree = ast.parse(code)

    analyzer = Analyzer()
    analyzer.walk(tree)
    analyzer.report()

def parse_imports(path: str):
    with open(path) as source:
        tree = ast.parse(source.read())

    analyzer = Analyzer()
    analyzer.walk_imports(tree)
    analyzer.report()


class Analyzer(ast.NodeVisitor):
    def __init__(self):
        self.stats = {"import": [], "from": {}, "if": [], "functionDef": [], "input": [], "open": [],
                      "functionCalls": []}

    def walk_imports(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.stats["import"].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.stats["from"].update({node.module: []})
                for alias in node.names:
                    self.stats["from"][node.module].append(alias.name)

    def walk(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                self.stats["if"].append(node.test.__str__())
            elif isinstance(node, ast.FunctionDef):
                self.stats["functionDef"].append(node.name)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ["input", "raw_input"]:
                        self.stats["input"].append(node.func.lineno)
                    elif node.func.id in ["open"]:
                        self.stats["open"].append(node.func.lineno)
                    else:
                        self.stats["functionCalls"].append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    self.stats["functionCalls"].append(node.func.value.__str__())
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.stats["import"].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.stats["from"].append(alias.name)

    def report(self):
        json_object = json.dumps(self.stats)
        print(json_object)


if __name__ == '__main__':
    if args.file:
        if args.struct:
            parser_file(args.file)
        elif args.imports:
            parse_imports(args.file)
        elif args.security:
            # subprocess.Popen(["virtualenv1/bin/python", "my_script.py"])
            # get last created directory in experiments
            last_created_dir = max(glob.glob("experiments/*"), key=os.path.getctime)
            proc = subprocess.run(["../venv/bin/pyre", "analyze", "--save-results-to", last_created_dir + "/" +args.file])
        elif args.slscan:
            last_created_dir = max(glob.glob("experiments/*"), key=os.path.getctime)
            os.makedirs(last_created_dir + "/" + args.file, exist_ok=True)
            client = docker.from_env()
            client.containers.run("shiftleft/scan", "scan", detach=False, remove=True, environment=[f"WORKSPACE={os.path.abspath(os.curdir)}/analysis/pysa"], volumes=[f"{os.path.abspath(os.curdir)}/analysis/pysa:/app"])
            # cmd = f"docker run --rm -e \"WORKSPACE={os.path.abspath(os.curdir)}/analysis/pysa\" -v {os.path.abspath(os.curdir)}/analysis/pysa:/app shiftleft/scan scan"
            # print(cmd)
            # proc = subprocess.check_call(sh_split(cmd))
            # proc = subprocess.run(["docker", "run", "--rm", "-e", "\"WORKSPACE=" + os.path.abspath(os.curdir) + "/analysis/pysa\"", "-v", os.path.abspath(os.curdir) + "/analysis/pysa:/app", "shiftleft/scan", "scan"])
            os.rename("analysis/pysa/reports", last_created_dir + "/" + args.file + "/reports")
        else:
            parser(args.code)
    elif args.analysis:
        for x in os.listdir(f"{args.analysis}"):
            if os.path.isdir(f"{args.analysis}/{x}") and os.path.exists(f"{args.analysis}/{x}/taint-python-report.json"):
                taint = json.load(open(f"{args.analysis}/{x}/taint-python-report.json"))
                for vuln in taint["vulnerabilities"]:
                    print(vuln["cwe_category"], vuln["severity"])


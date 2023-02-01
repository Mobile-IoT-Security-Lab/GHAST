import json
import re
import pickle
from enum import Enum
import requests
import argparse

parser = argparse.ArgumentParser(description='')
parser.add_argument("--src", dest='source', type=str)
parser.add_argument("--dest", dest="dest", type=str)
parser.add_argument("--token", dest="token", type=str)

args = parser.parse_args()

class critical_gh_context(Enum):
    ACTOR = "github.actor"
    PULL_REQUEST_BODY = "github.event.pull_request.body"
    PULL_REQUEST_TITLE = "github.event.pull_request.title"
    ISSUE_TITLE = "github.event.issue.title"
    ISSUE_BODY = "github.event.issue.body"
    ISSUE_COMMENT_BODY = "github.event.issue_comment.body"
    PULL_REQUEST_COMMENT_BODY = "github.event.pull_request_review_comment.body"


class critical_secrets(Enum):
    SECRET_CDD = "secrets."

class critical_permissions(Enum):
    ONLY_WF_DECLARATION = "Permissions declaration at workflow level"
    NO_DECLARATION = "Permissions are not declared in the workflow"
    PERMS_DISCREPANCY = "Permissions do not match the required ones"

class critical_tp_workflow(Enum):
    WF_OOD = "Workflow out of date"
    NO_PINNING = "Workflow not pinned at commit"


def getOODWf(wf):
    trueCount = 0
    falseCount = 0
    ret = []
    for j in wf['jobs']:
        for s in wf['jobs'][j]['steps']:
            sec = s.get('security', None)
            if sec:
                if sec.get('TP Actions Up-to-date') != None:
                    if sec.get('TP Actions Up-to-date'):
                        trueCount += 1
                    else:
                        falseCount += 1

    return trueCount, falseCount

def getOOD(wf):
    out_date = []
    ret = []
    for j in wf['jobs']:
        for s in wf['jobs'][j]['steps']:
            sec = s.get('security', None)
            if sec:
                if sec.get('TP Actions Up-to-date') != None:
                    out_date.append((j, s.get('uses'), sec.get('TP Actions Up-to-date')))

    return out_date

# %%
def getRuns(wf):
    _runs = []
    for j in wf['jobs']:
        for s in wf['jobs'][j]['steps']:
            sec = s.get('security')
            if sec.get('runs'):
                _runs.append(sec.get('runs'))
    return _runs
                

# %%
def getUses(repo):
    _uses = []
    _improper_use = []
    for wf in repo:
        for j in wf['jobs']:
            for s in wf['jobs'][j]['steps']:
                uses = s.get('uses', None)
                _uses.append(uses)
    return _uses

# %%
def getPerms(wf):
    _perms = {}
    _perms.update(wf=wf.get('permissions', None), jobs={})
    for j in wf['jobs']:
        _perms['jobs'].update({j: wf['jobs'][j].get('permissions')})
    return _perms

# %%
def main():
    dictwf = pickle.load(open(f"{args.source}/savedDictWfs.dat", "rb"))
    commit_rex = r"[0-9a-f]{40}"

    vulns = {}
    for wf_file in dictwf:
        vulns.update({wf_file: {}})
        for wf in dictwf.get(wf_file):
            _runs = getRuns(wf)
            _uses = getOOD(wf)
            _perms = getPerms(wf)
            if isinstance(wf.get('events'), dict):
                vulns[wf_file].update({wf.get('name'): {'events': (wf.get('events').get('type'), wf.get('events').get('security_rank')), "issues": []}})
            else:
                for e in wf.get('events'):
                    vulns[wf_file].update({wf.get('name'): {'events': (e.get('type'), e.get('security_rank')), "issues": []}})
                    
            if _runs != []:
                if _runs:
                    vulns[wf_file][wf.get('name')]['issues'].append(([i.name for i in critical_gh_context if i.value in ''.join(_runs[0][0]['line'])], ''.join(_runs[0][0]['line'])))
                    vulns[wf_file][wf.get('name')]['issues'].append(([i.name for i in critical_secrets if i.value in ''.join(_runs[0][0]['line'])], ''.join(_runs[0][0]['line'])))
            
            
            if len(_perms) > 0:
                wf_perms = False
                if _perms.get('wf') != 'None':
                    wf_perms = True
                for job_name, job_p in _perms.get('jobs').items():
                    if not job_p and wf_perms:
                        vulns[wf_file][wf.get('name')]['issues'].append((job_name, critical_permissions.ONLY_WF_DECLARATION.name))
                    elif not job_p and not wf_perms:
                        vulns[wf_file][wf.get('name')]['issues'].append((job_name, critical_permissions.NO_DECLARATION.name))
            api_url = "https://api.github.com/repos/" + wf_file + "/tags"
            req = requests.get(api_url, headers={"Authorization": "token " + args.token})
            tags = json.loads(req.text)
            if len(_uses) > 0:
                for ood in _uses:
                    if re.match(ood[1].split("@")[-1], commit_rex):
                        if not (ood[1].split("@")[-1] == tags[0].get('commit').get('sha')):
                            print("CASE")
                            vulns[wf_file][wf.get('name')]['issues'].append((ood[0], critical_tp_workflow.WF_OOD.name))
                    elif not ood[2] and not re.match(ood[1].split("@")[-1], commit_rex):
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], critical_tp_workflow.WF_OOD.name))
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], critical_tp_workflow.NO_PINNING.name))
                    elif not ood[2] and re.match(ood[1].split("@")[-1], commit_rex):
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], critical_tp_workflow.WF_OOD.name))
                    elif not re.match(ood[1].split("@")[-1], commit_rex):
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], critical_tp_workflow.NO_PINNING.name))
    with open(f"{args.dest}", "w") as f:
        f.write(json.dumps(vulns))

if __name__ == "__main__":
    main()





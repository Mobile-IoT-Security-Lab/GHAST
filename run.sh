#!/usr/bin/bash

./anonymized -sample samples/$1 -time $2 -gh-token <ghtoken>
exps_dir=$(ls -td experiments/* | head -n 1)
cat $exps_dir/workflow* > $exps_dir/workflow_tot.yml
python3 wfExtractor.py --wf $exps_dir/workflow_tot.yml --dest $exps_dir
python3 wfAnalyzer.py --src $exps_dir --dest $exps_dir/$1_report.json


#!/bin/bash

[[ -n "$1" ]] || { echo "Usage: $0 <output>"; exit 0 ; }
[[ ! -f "$1.jpg" ]] || { echo "File '$1.jpg' already exists"; exit 0; }

APPS="project account management infosec admin"
OUTPUT=$1

python ../manage.py graph_models $APPS -l dot > $OUTPUT.dot
dot -T jpg $OUTPUT.dot > $OUTPUT.jpg
rm -f $OUTPUT.dot


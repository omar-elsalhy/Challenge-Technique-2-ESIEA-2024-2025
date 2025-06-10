#!/bin/bash

###  Python file scorer, using pylint
###  Gauthier HEISS, 05/06/2022
###  gauthier.heiss@esiea.fr
###
###  Usage : ./score.sh [file]
###  If there is no file argument, the scorer will find recurcively all .py files

# Stop on error
set -e

# Clear "output.txt" file
echo "" > output.txt

# If there is no launching argument, find all files
if [[ $# -eq 0 ]]; then
    # Run pylint on all .py files recursively, and append results to output.txt
    script -q -c "pylint **/*.py --output-format=colorized" output.txt
else
    if [[ -f $1 ]]; then
        # Run shellcheck only on asked file
        script -q -c "pylint $1 --output-format=colorized" output.txt
    else
        echo -e "\e[31mNo such file or directory \"$1\"\e[0m"
        echo "---- Final score: ----"
        echo "0.00"
        exit
    fi
fi

# Line break
echo -e "\n"

# If there is a parsing error (which is fatal), give 0 as score
if grep -q "Parsing stopped here" output.txt; then
    echo -e "\e[31mFatal error in parsing\e[0m"
    echo "---- Final score: ----"
    echo "0.00"
    exit
fi

# Count stlye, info, warning and errors. "|| true" to ignore missing lines
errors=$(grep -c ": E" < output.txt || true)
warnings=$(grep -c ": W" < output.txt || true)
# infos=$(($(grep -c ": C" output.txt || echo 0) + $(grep -c ": R" output.txt || echo 0)))

# Displaying errors count
echo "---- Results: ----"
echo "Errors: ${errors}"
echo "Warnings: ${warnings}"
# echo "Style: ${infos}"

# Compute score
score=$(grep "Your code has been rated at" output.txt | awk '{print $7}' | cut -d'/' -f1)

# If score is negative, set to 0
if [[ ${score} == *-* ]]; then
    score="0.00"
fi

# Show score
echo -e "\n---- Final score: ----"
echo "${score}"
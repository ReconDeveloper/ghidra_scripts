#!/bin/bash


GHIDRA_PATH=~/ghidra_10.2.2_PUBLIC
GHIDRA_SCRIPT_PATH=~/ghidra_scripts

if [ "$#" -ne 1 ]
then 
    echo "$0 <current directory full path>"
    exit
fi
RED='\033[1;31m'
Green='\033[1;32m' 
# Start script timer 
start=$SECONDS
echo -e "---------------------Started Analyzing------------------------"
echo -e ""
for fileName in $(ls $(pwd)/binaries); do
    results_directory=$(pwd)/"${fileName}_results"
    mkdir -p $(pwd)/"${fileName}_results"
    result_xrefs="$results_directory/${fileName}_xrefs.txt"
    semgrep_source="$results_directory/${fileName}_semgrep_source.c"
    exported_source="$results_directory/${fileName}_exported_source.c"
    ghidra_project_name="${fileName}_ghidra_project"
    $GHIDRA_PATH/support/analyzeHeadless $1/"${fileName}_results" $ghidra_project_name -import "${1}/binaries/"$fileName  -scriptPath $GHIDRA_SCRIPT_PATH -postscript analyzer.py $result_xrefs $semgrep_source $exported_source
done

echo -e ""
echo -e "---------------------Finished Analyzing------------------------"
#End script timer
end=$SECONDS
duration=$(( end - start ))
if [ ${duration} -gt 3600 ]; then
        hours=$((duration / 3600))
        minutes=$(((duration % 3600) / 60))
        seconds=$(((duration % 3600) % 60))
        printf "${RED}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
elif [ ${duration} -gt 60 ]; then
        minutes=$(((duration % 3600) / 60))
        seconds=$(((duration % 3600) % 60))
        printf "${Green}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
else
        printf "${RED}Completed in ${duration} seconds\n"
fi
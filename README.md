#!/bin/bash

#this is my third project- about windows forensics.
#student name:Liad Bahari
#unit:JMagen773630, student code:S9
#lecture's name: Michael Elizerov
##########################
clear
echo "[***]script started."
sleep 2
echo
sleep 1
starting()
{
echo "[*] first, do you want to update and upgrade your system (y/n)?"
read system
if [ "$system" = "y" ]
then
	echo "[*] OK. updating your system right now."
	sudo apt update && sudo apt upgrade -y
else
	echo "[*] Got it, your choice (:"
fi
clear
}
####################
#1.1 Check the current user; exit if not ‘root’.
user_root()
{
clear
echo "[*] please wait, checking the user type - root/other.."
sleep 1
echo
if  [ "$(whoami)" = root ]
then
	echo "[+] You are root!, continuing.."
	sleep 2
else
	echo "[+] You are not root user, exiting..."
exit 1
fi
}
###########################33
filename=""
#1.2 Allow the user to specify the filename; check if the file exists.
check_filename()
{
sleep 2
clear
while true
do
echo "[+] please specify the full path of a memory File you want to check:"
read filename
if [ -f "$filename" ]
then
	filename=$(realpath "$filename")
	echo "[+] File $filename found!"
	sleep 2
	break
else
	echo
	echo "[+] $filename is not found. please enter a valid filename..."
fi 
done
echo


echo
echo "."
echo ".."
}
##############spare###########3
fix_broken_packages() 
{
sudo apt --fix-broken install -y &>/dev/null
sudo dpkg --configure -a &>/dev/null
clear
}
###############
#1.3 Create a function to install the forensics tools if missing.
install_apps()
{
clear
sleep 2
clear
echo "."
echo ".."
echo
echo "[*] Checking if the needed applications are installed"
echo
tools=(binwalk bulk_extractor foremost strings)
for tool in "${tools[@]}"
do
if command -v "$tool" &>/dev/null
then
	echo "[+] $tool already installed."
sleep 3
else
sleep 1
        echo "[*] $tool is missing, installing it right now!"
        sudo apt install -y "$tool" &> /dev/null

if [ "$tool" == "strings" ]
then
	sleep 2
	sudo apt install -y binutils &>/dev/null
fi
fi
sleep 2
done
sleep 1
echo
echo "[&] All tools installed sucessfully(:"
echo
echo "."
sleep 1
echo ".."
sleep 2
echo "..."
sleep 4
clear
}
##################################333
###volatility part.
volatility_part()
{
if [ -d "volatility" ]
then
        echo "[*] Volatility  already downloaded. Skipping download."
else
        echo "[*] volatility is not installed. installing it now..."
sleep 1
echo "[*] credit to chatGPT"
sleep 2
sudo wget -nc http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip 
unzip -j -o volatility_2.6_lin64_standalone.zip 
sudo chmod -R 777 volatiltiy_2.6_lin64_standalone
fi


echo "[*] checking if Volatility was downloaded successfully..."
echo "."

./volatility_2.6_lin64_standalone -h
echo
sleep 1
echo "[*] volatilty installed successfully (:"

sleep 2
clear


}
######################
#starting extract data:
#1.4 Use different carvers to automatically extract data.
#1.5 Data should be saved into a directory.
########################3
extract_data()
{
start_time=$(date +%s)
echo "$filename"
sleep 1
clear
echo "."
sleep 1
echo
echo ".."
#########
##creating a directory for the next step
echo "[*] now, creating a Directory to include all data..."
sleep 3
Data_Directory="ExtractedDATA"

mkdir -p $HOME/Desktop/"$Data_Directory"
if [ ! -d "$HOME/Desktop/$Data_Directory" ]
then
	echo "❌ Failed to create directory $Data_Directory"
	exit 1
fi
sleep 3
#using the suggested tools to extract the data
echo
echo "[*] wait while extracting data with the following tools:"
echo
#using foremost
echo "[+] foremost:"
sleep 2
echo
foremost -i "$filename" -o $HOME/Desktop/"$Data_Directory"/foremostDATA -T
echo "[*] foremost data is now at the directory!"
sleep 2

echo
#using bulk_extratcor
echo "[+] bulk_extratcor:"
sleep 2
echo
bulk_extractor  "$filename" -o $HOME/Desktop/"$Data_Directory"/BulkOutput
echo
echo "[*] bulk_extractor data is now at the directory."
sleep 2

echo 
#using binwalk
echo "[+] binwalk:"
sleep 2
echo
binwalk "$filename" > $HOME/Desktop/"$Data_Directory"/BinwalkOutput
echo "[*] binwalk data is now at the directory too!"
sleep 2

echo
#using stirngs
echo "[+] strings:"
sleep 2
echo
strings "$filename" > $HOME/Desktop/"$Data_Directory"/StringsOutput
echo "[*] strings data is now at the directory too!"
sleep 2
echo
echo
sleep 1 
echo "[**] Alrihgt!, Data saved into 'root/Desktop/ExtractedDATA'."
sleep 2
echo
echo "[!!] Attention! the directory must run from root directory!. /root/Desktop/ExtractedDATA"
sleep 5
##########################
#1.6 Attempt to extract network traffic; if found, display to the user the location and size.
##########################
clear
sleep 2
output_directory=$HOME/Desktop/"$Data_Directory"
pcap_directory="$output_directory"/pcap_files

mkdir -p "$pcap_directory"

pcap_files=$(find "$output_directory" -type f -name "*.pcap")

#checking if found pcap files for network
if [ -z "$pcap_files" ]
then
	echo "[*] No .pcap files found in $output_directory."
else
	echo "$pcap_files" | while IFS= read -r file
do
   	cp "$file" "$pcap_directory"
    	echo "[+] Copied $file to $pcap_directory"
	echo
sleep 2
file_size=$(stat -c%s "$file")
	echo "[+] the file $file size is $file_size bytes"
sleep 3
done
echo
  	echo "[+] All .pcap files have been copied to $pcap_directory."
fi
sleep 4
echo "[**] continue now.."
}
##########
#1.7 Check for human-readable (exe files, passwords, usernames, etc.).
human_readable()
{
echo
sleep 1
output_file=$HOME/Desktop/"$ExtractedDATA"/human_readable_with-strings.txt

echo "[*] checking for human-readable with strings command..."

strings "$filename" | grep -Ei 'password|username|user|pass' > "$output_file"

#check if we got something with strings
sleep 5
clear
if [ -s "$output_file" ]
then
	echo "[*] Found human-readable with strings that related to password and username!, the results have been saved to $output_file"
else
  	echo "[*] No relevant human-readable strings found."
fi
sleep 5
clear
}

################
       #2
################
#2.1 Check if the file can be analyzed in Volatility; if yes, run Volatility. 
volatility_analysis()
{
filename="$filename"
output_dir=$HOME/Desktop/"$Data_Directory"
#checking the file type. - if it memory file, it could be run with.
echo "[*] checking if file type is a memory file...."
echo "."
echo "..."
sleep 1
valid_types=("raw" "bin" "vmem" "mem" "dmp")
extension="${filename##*.}"

if [[ " ${valid_types[@]} " =~ " ${extension} " ]]
then
	echo -e "[+] the file $filename type is a valid memory file. we move on \u2192."
	sleep 2
	echo "[*] running volatility."
	sleep 1
	command=$(./volatility_2.6_lin64_standalone -f "$filename" imageinfo)
	echo "$command"
	command_filter=$(echo "$command" | grep -oP 'Win[^ ,]+|Vista[^ ,]+' | sort -u | head -n 1)
	sleep 4
	clear
#2.2 Find the memory profile and save it into a variable.
	#saving profile as a variable.
	echo "[*] the profile is: $command_filter"
profile_name="$command_filter"
echo
sleep 3
echo "[*] volatility run sueccessfully."
echo
echo "[+] and the profile has been save as a variable"
sleep 4
echo
clear
#if fileType is not match.
else
	echo "[-] Error: The file type .$extension is NOT a valid memory file!"
fi
################################################
sleep 4
clear
###############
#2.3 Display the running processes.
###############
echo -e "[*] preparing to show running proccess: \u2193"
sleep 1
./volatility_2.6_lin64_standalone -f "$filename" --profile="$profile_name" pslist
sleep 12
clear
sleep 2
clear
#####################
#2.4 Display network connections.
#####################
if [[ "$profile_name" == WinXPSP2x86 || "$profile_name" == WinXPSP3x86 || \
"$profile_name" == WinXPSP2x64 || "$profile_name" == WinXPSP3x64 || \
"$profile_name" == WinXPx86 ]]
then
	echo "[*] Windows XP can be running only with connscan"
	./volatility_2.6_lin64_standalone -f "$filename" --profile="$profile_name" connscan
	sleep 4
else
	echo "[*] The following OS version can be running with netscan command (:."
	sleep 4
	echo "displaying Network connection:"
	echo
	./volatility_2.6_lin64_standalone -f "$filename" --profile="$profile_name" netscan
sleep 15
fi
#####################
#2.5 Attempt to extract registry information. 
#####################
clear
echo "."
echo "[*] extracting registry information now. ↓"
sleep 1
./volatility_2.6_lin64_standalone -f "$filename" --profile="$profile_name" hivelist
sleep 15
}
#######################
#3.1 Display general statistics (time of analysis, number of found files, etc.).
#3.2 Save all the results into a report (name, files extracted, etc.).
#3.3 Zip the extracted files and the report file.

#######################


results_part()
{
clear
echo "."
echo "[*] now. showing the results:"
end_time=$(date +%s)
All_AnalysisTime=$((end_time - start_time))
echo "[*] Time of analysis: $All_AnalysisTime seconds"
sleep 1
echo "[*] number of extracted files: $(find "$output_directory" -type f |wc -l)"
sleep 2

#saving the report file
report_file="$HOME/Desktop/ExtractedDATA/report.txt"
echo "[*] Saving results to report file..."
sleep 1
echo "[*] Analysis Time: $All_AnalysisTime seconds" > "$report_file"
echo "[*] Number of extracted files: $(find "$output_directory" -type f | wc -l)" >> "$report_file"
echo "[*] Files extracted:" >> "$report_file"
sleep 3
find "$output_directory" -type f >> "$report_file"
echo "[*] Report saved to: $report_file"
sleep 7
clear
#ZIPing the extracted files.
echo "[*] zipping the extracted files and the report file into a 'zip'."
zip_file="$HOME/Desktop/ExtractedDATA.zip"
zip -r "$zip_file" "$HOME/Desktop/ExtractedDATA"
echo "[*] zip file was created at: $zip_file"
sleep 1
echo
echo ":)"

}


#Call the functions:
starting
user_root
check_filename
fix_broken_packages
install_apps
volatility_part
extract_data
human_readable
volatility_analysis
results_part

echo
echo "[*] script completed."

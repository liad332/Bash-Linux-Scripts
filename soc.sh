#!/bin/bash
##############################
echo "HI, welcome to my SOC Project."
# author name: LIAD BAHARI.
sleep 1

root()
{
echo "Checking if You are root..."
echo
sleep 1
if [ $(whoami) = root ]
then
	echo "You are root. GREAT!"
else
	echo "please try again using 'root' - an higher priviligies.."
	exit 1
fi	
clear	
}


Avail_IP()
{
echo "Im going to display all available IP addressess:"
echo
read -p "For that i need your net-ID (for exam: 192.168.1.0/24 :  IP with CIDR):" NET 
if [[ "$NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/(3[0-2]|[1-2]?[0-9])$ ]]
then
	echo "OK. we are moving on.."
	echo
	echo "This are the available IP's:"
	netdiscover -P -r "$NET" | awk '{print $1}'
	lsIP=$(netdiscover -P -r "$NET" | awk '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ { for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i }' | sort -u | shuf -n1) 
	
	read -p "To continue? (Press ENTER):"
	return
else
	echo "WRONG input, run the script again."
	exit 1
fi	
}

IP_Select()
{
read -p "alright.choose if you want to put an IP address for the attack, OR select one randomali from the options shown above (in the previous Q..): -- ('S' for select by yourself, 'R' - for random):" IPs
if [[ "$IPs" == S || "$IPs" == s ]]
then
	read -p "OK. write an IP you prefer:" USERIP
	if [[ "$USERIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
	then
		echo "IP is OK, continuning to the attack step :) ."
		return
	else 
	echo "IP is not OK. try again from the begginning..."
	exit 1
	fi
elif [[ "$IPs" == R || "$IPs" == r ]]
then
	echo "$lsIP"
	return
else
	echo "pls enter a valid answer..."
	exit 1
fi	


}






clear

Attacks()
{
Targ_IP="${USERIP:-$lsIP}"
echo "Using IP: $Targ_IP"	
	
sleep 1
echo
printf "Available attacks (descriptions):\n\n"

    printf "1) Brute-force\n"
    printf "   - Description: Attempts to discover valid credentials by trying many username/password\n"
    printf "     combinations. (In this script: SIMULATED only ֳ¢ג‚¬ג€ do not run against real targets.)\n\n"

    printf "2) Banner Grabbing\n"
    printf "   - Description: The technique of capturing information from a remote computer\n"
    printf "     system's open network ports to identify the OS, services and version running\n\n"

    printf "3) Vulnerability Scan\n"
    printf "   - Description: Scans target services for known vulnerabilities and reports potential\n"
    printf "     CVEs and risk levels. (In this script: SIMULATED / reporting mode.)\n\n"

sleep 1
echo
sleep 2
read -p "please tell us if you want to choose the type of the attack OR to let us do a random chosing (ran / letme):" OR
if [ "$OR" = "ran" ]  
then # generate 1..3
	echo "OK. doing it for u."
	sleep 2
	echo
    choice=$(( (RANDOM % 3) + 1 ))
    case "$choice" in
        1) echo "Random choice: Banner Grabbing"; Banner ;;
        2) echo "Random choice: BruteForce"; BruteForce ;;
        3) echo "Random choice: VulnerabilityScan"; VulnerabillityScan ;;
    esac
elif [ "$OR" = "letme" ]   
then
	echo "You will choose an attack on your-self"
	read -p "choose from: (exam: 1/2/3 - only one number.):" user_choice
else
	echo "Try running the script again with correct input..."
	exit 0
fi
echo "$user_choice"
sleep 2
clear
if [ "$user_choice" = "1" ] 
then
	echo
	echo "BruteForce One."
	sleep 1
	echo 
	sleep 1
	BruteForce	
	exit
elif [ "$user_choice" = "2" ]
then
	echo
	echo "Banner Grabbing One."
	sleep 1
	echo
	Banner
	exit
elif [ "$user_choice" = "3" ]
then
	echo
	echo "Vulnerablity Scanning One."
	sleep 1
	echo
	VulnerabillityScan
	exit
elif [ -n "$user_choice" ]
then
	exit 1
	echo "script completed."
	else
		echo "Not an option - good bye."
		exit 1
fi	
}


#the Attacks

#1
BruteForce()
{
clear
echo	
echo "now we are going to do this attack :)"	
sleep 2

read -p "Please specify a user you know that exist to the machine we gonna attack:" u

read -p "wordlist/pass ? (please write it as upper: PASS / WORDLIST ):" p


if [ "$p" =  WORDLIST ]
then
	echo "continue with PASS WORDLIST"
	echo
	read -p "please specify the path to it (EXAM: /home/kali/wordlist.txt):" WORDLIST
	if [[ -f "$WORDLIST" && -r "$WORDLIST" ]]
	then
		echo "Path is OK."
	else
		echo "Path is invalid."
		exit 1
	fi	
	echo
	sleep 2
	echo "OK Running Hydra tool on $Targ_IP with $u and $p for ftp service."
	sleep 1
	echo
	hydra -l $u -P $WORDLIST ftp://$Targ_IP
elif [ "$p" =  PASS ]
then
	echo "continue with PASS"
	echo
	read -p "ENTER PASS:" PASS
	sleep 1
	echo "starting hydra tool on $Targ_IP with $u and $p for ftp service."
	echo
	hydra -l $u -p $PASS ftp://$Targ_IP
else
	echo "WRONG Input..."
	exit 1
fi
typeAT="Brute_Force"
time="$(date)"
logfile="/var/log/SOCproject.log"
echo "$time | $typeAT | TargetIP:$Targ_IP" >> "$logfile"
read -p "continue? (ENTER):"
echo "Attack completed, and there is a log file with info at /var/log/SOCproject.log."
sleep 5

	
}







#2
Banner()
{
clear
echo "Starting the Banner Grabbing attack:"
echo
nmap -sS --top-ports 100 --script banner $Targ_IP
echo
sleep 2
read -p "to countinue? (ENTER):"
echo "ok. now we are extracting only the banners - to a txt file, will be at /$(pwd) (only_banner.txt)"
echo
sleep 1
banner=$(nmap -sS --top-ports 100 --script banner $Targ_IP | grep -i '_banner')
echo $banner >> "/$(pwd)/Only_Banner.txt"
echo
typeAT="Banner_Grabbing"
time="$(date)"
logfile="/var/log/SOCproject.log"
echo "$time | $typeAT | TargetIP:$Targ_IP" >> "$logfile"
sleep 1
echo  "Attack completed, and there is a log file with info at /var/log/SOCproject.log."
sleep 5
}




#3
VulnerabillityScan()
{
clear	
echo "Starting the 'Scanning for VULNs' attack:"
echo 
sleep 1
nmap -sV --script=vuln "$Targ_IP"
typeAT="Vulnerabillity_Scan"
time="$(date)"
logfile="/var/log/SOCproject.log"
echo "$time | $typeAT | TargetIP:$Targ_IP" >> "$logfile" 	
read -p "continue? (ENTER):"
echo "Attack completed, and there is a log file with info at /var/log/SOCproject.log."
sleep 5
}



# i'm calling to the functions
root
Avail_IP
IP_Select
Attacks
echo "Script Completed."
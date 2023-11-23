#!/bin/bash

# Function to print colorized messages
print_message() {
    local color=$1
    local message=$2
    echo -e "\e[${color}m${message}\e[0m"
}

# Function to display summary
display_summary() {
    local vulnerable_ports=("$@")
    if [ "${#vulnerable_ports[@]}" -eq 0 ]; then
        print_message 4 "Summary: No vulnerabilities found on any port."
    else
        print_message 2 "Summary: Vulnerabilities found on the following ports: ${vulnerable_ports[@]}"
    fi
}

# Function to enforce https if 443 is used
enforce_https() {
    local port=$1
    if [ "$port" -eq 443 ]; then
        protocol="https"
    else
        protocol="http"
    fi
    echo "$protocol"
}

# Check if the user has provided the required arguments
if [ "$#" -lt 2 ]; then
    print_message 1 "Usage: $0 [-f <target_file> | <target_url>] -p <ports>"
    print_message 1 "nvz"
    exit 1
fi

# Parse command line options
while getopts ":f:p:" opt; do
    case $opt in
        f)
            target_file="$OPTARG"
            if [ ! -e "$target_file" ]; then
                print_message 1 "Error: Target file '$target_file' not found."
                exit 1
            fi
            targets=($(sort "$target_file" | uniq))
            ;;
        p)
            ports=($OPTARG)
            ;;
        \?)
            print_message 1 "Invalid option: -$OPTARG"
            exit 1
            ;;
        :)
            print_message 1 "Option -$OPTARG requires an argument."
            exit 1
            ;;
    esac
done

# If target file is not provided, use the positional argument as target URL
if [ -z "$target_file" ]; then
    targets=("$1")
fi

# Check if ports are provided
if [ -z "${ports[*]}" ]; then
    print_message 1 "Error: Port(s) not specified. Use -p option to specify port(s)."
    exit 1
fi

# Log file path
log_file="host_header_poisoning_log.txt"
counter=0

# Check if the log file already exists, if yes, append a number to the file name
while [ -e "$log_file" ]; do
    counter=$((counter + 1))
    log_file="host_header_poisoning_log_${counter}.txt"
done

# Array to store vulnerable ports
vulnerable_ports=()

# Loop through targets and ports
for target in "${targets[@]}"; do
    for port in "${ports[@]}"; do
        protocol=$(enforce_https "$port")

        # Create a list of paths to check
        paths=("/index.php" "/icons/small" "/user_guide" "/" "/phpmyadmin")  

        for path in "${paths[@]}"; do
            # Create a malicious HTTP request using curl and redirect output to log file
            response=$(curl -s -k -i -H "Host: attacker.com" --max-time 2 "${protocol}://${target}:${port}${path}")

            # Check if the request timed out
            if [ $? -ne 0 ]; then
                print_message 3 "[-] Timeout: Request to ${target}:${port} timed out for path ${path}."
                continue  # Move to the next path
            fi

            # Display the relevant portion of the response in the log file
            echo -e "\n========== Request for target: ${target}, Port: ${port}, Path: ${path} ==========\n" >> "$log_file"
            echo -e "${response}" | awk '/attacker\.com/ {print NR ": " $0; found=1} {a[i++]=$0} END {if (found) for (j=NR-3; j<=NR+3; j++) print j ": " a[j]}' >> "$log_file"

            # Check if "attacker.com" is present in the response (case-insensitive)
            if (echo "$response" | grep -i "attacker.com" >/dev/null); then
                print_message 2 "[+] Vulnerability found on port ${port} for ${target} with path ${path}" >> "$log_file"
                print_message 3 "[+] Vulnerability found on port ${port} for ${target} with path ${path}" 
                # Add the vulnerable port to the array
                vulnerable_ports+=("${target}:${port}")
            fi
        done
    done
done

# Display summary
display_summary "${vulnerable_ports[@]}"

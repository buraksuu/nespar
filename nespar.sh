#!/bin/bash

OUTPUT_FILE=""
EXCLUDE_PORT=false

RED='\033[38;5;196m'
ORANGE='\033[38;5;208m'
YELLOW='\033[38;5;220m'
GREEN='\033[38;5;40m'
BLUE='\033[38;5;45m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m'

FILE=$(ls scan_results_hosts_ports.txt 2>/dev/null | head -n1)

if [[ ! -f "$FILE" ]] && [[ "$1" != "run" ]]; then
    echo -e "${RED}Error: File not found${NC}"
    echo -e "${YELLOW}Required: scan_results_hosts_ports.txt${NC}"
    echo -e "${CYAN}Tip: Run 'nespar run' first to process CSV files${NC}"
    exit 1
fi

save_output() {
    local content="$1"
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "$content" | tee "$OUTPUT_FILE"
        echo "Output saved: $OUTPUT_FILE"
    else
        echo "$content"
    fi
}

process_csv_files() {
    local VULNS_OUTPUT_FILE="scan_results_hosts_ports.txt"
    local HOSTS_OUTPUT_FILE="nessus-hosts.txt"

    echo "Starting CSV processing..."

    if ! ls *.csv 1> /dev/null 2>&1; then
        echo "Error: No CSV files found in current directory!"
        echo "Please ensure you have Nessus CSV export files in the current directory"
        exit 1
    fi

    rm -f "${VULNS_OUTPUT_FILE}.tmp"

    for report in *.csv; do
        if [ ! -f "$report" ]; then
            echo "No CSV files found!"
            exit 1
        fi


        tr -d '\n\r' <"${report}" | sed -e 's/""\([0-9]\+\)"/"\n"\1"/g;s/,Plugin Output"/,Plugin Output\n"/g' >"${report}.tmp"


        for severity in Critical High Medium Low None; do
            grep "\"${severity}\"" "${report}.tmp" | cut -d'"' -f16 | sort | uniq | grep -v '^$' | while read vuln; do
                echo -n "${severity};${vuln};"
                grep "\"${vuln}\"" "${report}.tmp" | cut -d '"' -f10,14 | sort -V | uniq | tr '\n' ',' | sed -e 's/"/:/g;s/,/, /g;s/, $//g'
                echo
            done
        done >>"${VULNS_OUTPUT_FILE}.tmp"

        rm -f -- "${report}.tmp"
    done


    cat "${VULNS_OUTPUT_FILE}.tmp" | cut -d';' -f1,2 | sort | uniq | while read vuln; do
        echo -n "${vuln};"
        cat "${VULNS_OUTPUT_FILE}.tmp" | grep "^${vuln};" | cut -d';' -f3 | tr -d ',' | tr -s ' ' '\n' | sort -V | uniq | tr '\n' ',' | sed -e 's/,/, /g;s/, $//'
        echo
    done > "${VULNS_OUTPUT_FILE}.final"

    for severity in Critical High Medium Low None; do
        grep "^${severity};" "${VULNS_OUTPUT_FILE}.final"
    done > "${VULNS_OUTPUT_FILE}"

    rm -f "${VULNS_OUTPUT_FILE}.tmp" "${VULNS_OUTPUT_FILE}.final"

    echo "Complete - vulnerability report saved to ${VULNS_OUTPUT_FILE}"


    for report in *.csv; do

        tr -d '\n\r' <"${report}" | sed -e 's/""\([0-9]\+\)"/"\n"\1"/g;s/,Plugin Output"/,Plugin Output\n"/g' >"${report}.tmp"

        if [ -f "${report/.csv/}-${HOSTS_OUTPUT_FILE}" ]; then
            :
        else
            grep '","[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+","' <"${report}.tmp" | \
                cut -d',' -f5 | tr -d '"' | sort -V | uniq >"${report}-${HOSTS_OUTPUT_FILE}.tmp"
            mv -f -- "${report}-${HOSTS_OUTPUT_FILE}.tmp" "${report/.csv/}-${HOSTS_OUTPUT_FILE}"
        fi

        rm -f -- "${report}.tmp"
    done

    cat *-${HOSTS_OUTPUT_FILE} | sort -V | uniq > ${HOSTS_OUTPUT_FILE}.tmp
    mv -f ${HOSTS_OUTPUT_FILE}.tmp ${HOSTS_OUTPUT_FILE}
    echo "Complete - unique hosts saved to ${HOSTS_OUTPUT_FILE}"
    rm -f *-${HOSTS_OUTPUT_FILE}

    echo ""
    echo "Files created:"
    echo "  - ${VULNS_OUTPUT_FILE} (Vulnerabilities With Ports)"
    echo "  - ${HOSTS_OUTPUT_FILE} (Nessus Host IPs)"
    echo ""
    echo "You can now use other nespar commands to query this data."
}

extract_hosts() {
    local OUTPUT_FILE="nessus-hosts.txt"

    if ! ls *.csv 1> /dev/null 2>&1; then
        echo "Error: No CSV files found in current directory!"
        echo "Please ensure you have Nessus CSV export files in the current directory"
        exit 1
    fi

    rm -f "${OUTPUT_FILE}" "${OUTPUT_FILE}.tmp"

    for report in *.csv; do

        tr -d '\n\r' <"${report}" | sed -e 's/""\([0-9]\+\)"/"\n"\1"/g;s/,Plugin Output"/,Plugin Output\n"/g' >"${report}.tmp"

        echo "Extracting hosts from ${report}"

        awk -F',' '{
            for(i=1; i<=NF; i++) {
                gsub(/"/, "", $i);
                if($i ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
                    print $i;
                }
            }
        }' "${report}.tmp" | sort -V | uniq >> "${OUTPUT_FILE}.tmp"

        grep -oE '"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"' "${report}.tmp" | \
            tr -d '"' | sort -V | uniq >> "${OUTPUT_FILE}.tmp"

        rm -f -- "${report}.tmp"

        if [ -f "${OUTPUT_FILE}.tmp" ]; then
            current_count=$(cat "${OUTPUT_FILE}.tmp" | sort -V | uniq | wc -l)
            echo "Found ${current_count} unique hosts so far"
        fi
    done

    if [ -f "${OUTPUT_FILE}.tmp" ]; then
        echo "Consolidating all host lists"
        cat "${OUTPUT_FILE}.tmp" | sort -V | uniq > "${OUTPUT_FILE}"
        rm -f "${OUTPUT_FILE}.tmp"

        final_count=$(wc -l < "${OUTPUT_FILE}")
        echo "Complete - ${final_count} unique hosts saved to ${OUTPUT_FILE}"
        echo ""
        echo "File created: ${OUTPUT_FILE}"
        echo "Sample hosts:"
        head -5 "${OUTPUT_FILE}"
    else
        echo "No hosts found in CSV files"
        echo "This might indicate:"
        echo "1. CSV format is different than expected"
        echo "2. No scan data in the CSV files"
        echo "3. CSV files contain only headers"
        echo ""
        echo "Please check your CSV file format and content"
    fi
}

analyze_vulnerabilities() {
    echo "=== VULNERABILITY ANALYSIS REPORT ==="
    echo "$(date)"
    echo ""

    if [[ ! -f "$FILE" ]]; then
        echo "Error: No vulnerability data found!"
        echo "Run 'nespar run' first to process CSV files"
        exit 1
    fi

    echo "Data source: $FILE"
    echo ""

    critical_count=$(grep "^Critical;" "$FILE" | wc -l)
    high_count=$(grep "^High;" "$FILE" | wc -l)
    medium_count=$(grep "^Medium;" "$FILE" | wc -l)
    low_count=$(grep "^Low;" "$FILE" | wc -l)
    info_count=$(grep "^None;" "$FILE" | wc -l)

    total_vulns=$((critical_count + high_count + medium_count + low_count + info_count))

    echo "VULNERABILITY COUNT BY SEVERITY:"
    echo "=================================="
    printf "${RED}%-12s${NC}: %s\n" "Critical" "$critical_count"
    printf "${ORANGE}%-12s${NC}: %s\n" "High" "$high_count"
    printf "${YELLOW}%-12s${NC}: %s\n" "Medium" "$medium_count"
    printf "${GREEN}%-12s${NC}: %s\n" "Low" "$low_count"
    printf "${BLUE}%-12s${NC}: %s\n" "Info" "$info_count"
    echo "=================================="
    printf "%-12s: %s\n" "TOTAL" "$total_vulns"
    echo ""
}

interactive_menu() {
    if [[ ! -f "$FILE" ]]; then
        echo -e "${RED}Error: No vulnerability data found!${NC}"
        echo -e "${CYAN}Run 'nespar run' first to process CSV files${NC}"
        exit 1
    fi

    while true; do
        echo ""
        echo -e "${BOLD}${BLUE}=== NESPAR INTERACTIVE MENU ===${NC}"
        echo -e "${WHITE}1${NC} - ${CYAN}Browse by Severity${NC}"
        echo -e "${WHITE}2${NC} - ${CYAN}Browse by All Vulnerability${NC}"
        echo -e "${WHITE}3${NC} - ${CYAN}Search by Port${NC}"
        echo -e "${WHITE}4${NC} - ${CYAN}Search by Term${NC}"
        echo -e "${WHITE}5${NC} - ${CYAN}Show Analysis Report${NC}"
        echo -e "${WHITE}0${NC} - ${RED}Exit${NC}"
        echo ""
        read -p "$(echo -e ${YELLOW}Select an option [0-5]: ${NC})" main_choice

        case "$main_choice" in
            1)
                browse_by_severity
                ;;
            2)
                browse_by_info
                ;;
            3)
                search_by_port
                ;;
            4)
                search_by_term
                ;;
            5)
                analyze_vulnerabilities
                read -p "$(echo -e ${YELLOW}Press Enter to continue...${NC})"
                ;;
            0)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please select 0-5.${NC}"
                ;;
        esac
    done
}

browse_by_severity() {
    echo ""
    echo -e "${BOLD}${BLUE}=== SELECT SEVERITY LEVEL ===${NC}"

    critical_count=$(grep "^Critical;" "$FILE" | wc -l)
    high_count=$(grep "^High;" "$FILE" | wc -l)
    medium_count=$(grep "^Medium;" "$FILE" | wc -l)
    low_count=$(grep "^Low;" "$FILE" | wc -l)
    info_count=$(grep "^None;" "$FILE" | wc -l)

    echo -e "${WHITE}1${NC} - ${RED}Critical${NC} (${BOLD}$critical_count${NC} vulnerabilities)"
    echo -e "${WHITE}2${NC} - ${ORANGE}High${NC} (${BOLD}$high_count${NC} vulnerabilities)"
    echo -e "${WHITE}3${NC} - ${YELLOW}Medium${NC} (${BOLD}$medium_count${NC} vulnerabilities)"
    echo -e "${WHITE}4${NC} - ${GREEN}Low${NC} (${BOLD}$low_count${NC} vulnerabilities)"
    echo -e "${WHITE}5${NC} - ${BLUE}Info${NC} (${BOLD}$info_count${NC} vulnerabilities)"
    echo -e "${WHITE}0${NC} - ${PURPLE}Back to main menu${NC}"
    echo ""

    read -p "$(echo -e ${YELLOW}Select severity [0-5]: ${NC})" severity_choice

    case "$severity_choice" in
        1) selected_severity="Critical" ;;
        2) selected_severity="High" ;;
        3) selected_severity="Medium" ;;
        4) selected_severity="Low" ;;
        5) selected_severity="None" ;;
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}"; return ;;
    esac

    show_vulnerabilities_by_severity "$selected_severity"
}

show_vulnerabilities_by_severity() {
    local severity="$1"

    local display_severity="$severity"
    if [[ "$severity" == "None" ]]; then
        display_severity="Info"
    fi

    local severity_color
    case "$severity" in
        "Critical") severity_color="${RED}" ;;
        "High") severity_color="${ORANGE}" ;;
        "Medium") severity_color="${YELLOW}" ;;
        "Low") severity_color="${GREEN}" ;;
        "None") severity_color="${BLUE}" ;;
    esac

    echo ""
    echo -e "${BOLD}${severity_color}=== $display_severity VULNERABILITIES ===${NC}"

    local vulns_file=$(mktemp)
    grep "^$severity;" "$FILE" | cut -d';' -f2 > "$vulns_file"

    local vulns=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && vulns+=("$line")
    done < "$vulns_file"
    rm -f "$vulns_file"

    if [[ ${#vulns[@]} -eq 0 ]]; then
        echo -e "${RED}No vulnerabilities found for $display_severity severity.${NC}"
        read -p "$(echo -e ${YELLOW}Press Enter to continue...${NC})"
        return
    fi

    for i in "${!vulns[@]}"; do
        printf "${WHITE}%2d${NC} - ${severity_color}%s${NC}\n" $((i+1)) "${vulns[$i]}"
    done
    echo ""
    echo -e "${WHITE}0${NC} - ${PURPLE}Back to severity menu${NC}"
    echo ""

    read -p "$(echo -e ${YELLOW}Select vulnerability to view affected hosts [0-${#vulns[@]}]: ${NC})" vuln_choice

    if [[ "$vuln_choice" == "0" ]]; then
        return
    elif [[ "$vuln_choice" -ge 1 && "$vuln_choice" -le ${#vulns[@]} ]]; then
        local selected_vuln="${vulns[$((vuln_choice-1))]}"
        show_affected_hosts "$selected_vuln"
    else
        echo -e "${RED}Invalid option.${NC}"
    fi
}

browse_by_info() {
    echo ""
    echo -e "${BOLD}${BLUE}=== ALL VULNERABILITIES ===${NC}"

    echo -e "${CYAN}Loading all vulnerabilities...${NC}"
    echo ""

    local counter=1
    while IFS=';' read -r severity vuln_name rest; do
        if [[ -n "$severity" && -n "$vuln_name" ]]; then
            case "$severity" in
                "Critical")
                    echo -e "${WHITE}$counter${NC} - ${RED}[Critical]${NC} $vuln_name"
                    ;;
                "High")
                    echo -e "${WHITE}$counter${NC} - ${ORANGE}[High]${NC} $vuln_name"
                    ;;
                "Medium")
                    echo -e "${WHITE}$counter${NC} - ${YELLOW}[Medium]${NC} $vuln_name"
                    ;;
                "Low")
                    echo -e "${WHITE}$counter${NC} - ${GREEN}[Low]${NC} $vuln_name"
                    ;;
                "None")
                    echo -e "${WHITE}$counter${NC} - ${BLUE}[Info]${NC} $vuln_name"
                    ;;
            esac
            ((counter++))
        fi
    done < "$FILE"

    echo ""
    echo -e "${WHITE}0${NC} - ${PURPLE}Back to main menu${NC}"
    echo ""

    local total_vulns=$((counter - 1))
    read -p "$(echo -e ${YELLOW}Select vulnerability to view affected hosts [1-$total_vulns]: ${NC})" vuln_choice

    if [[ "$vuln_choice" == "0" ]]; then
        return
    elif [[ "$vuln_choice" =~ ^[0-9]+$ ]] && [[ "$vuln_choice" -ge 1 && "$vuln_choice" -le $total_vulns ]]; then
        local selected_vuln=$(sed -n "${vuln_choice}p" "$FILE" | cut -d';' -f2)
        show_affected_hosts "$selected_vuln"
    else
        echo -e "${RED}Invalid option.${NC}"
    fi
}

show_affected_hosts() {
    local vuln_name="$1"
    echo ""
    echo "=== AFFECTED HOSTS ==="
    echo "Vulnerability: $vuln_name"
    echo ""

    local hosts=$(grep -F "$vuln_name" "$FILE" \
        | tr ',' '\n' \
        | sed 's/^[ \t]*//;s/[ \t]*$//' \
        | tr ';' '\n' \
        | grep -v "None" \
        | grep -vF "$vuln_name" \
        | grep -Ev "Critical|Medium|High|Low|None" \
        | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$" \
        | sort -u)

    if [[ -z "$hosts" ]]; then
        echo "No affected hosts found."
        echo ""
        echo "Options:"
        echo "1 - Save empty result to file"
        echo "0 - Back"
        echo ""
        read -p "Select option [0-1]: " empty_choice
        case "$empty_choice" in
            1)
                read -p "Enter filename: " filename
                if [[ -n "$filename" ]]; then
                    echo "No affected hosts found for: $vuln_name" > "$filename"
                    echo "Empty result saved to $filename"
                fi
                read -p "Press Enter to continue..."
                ;;
            0|*)
                return
                ;;
        esac
        return
    else
        echo "$hosts"
        echo ""
        echo "Total affected hosts: $(echo "$hosts" | wc -l)"
    fi

    echo ""
    echo "Options:"
    echo "1 - Show IPs only (without ports)"
    echo "2 - Save hosts with ports to file"
    echo "0 - Back"
    echo ""

    read -p "Select option [0-2]: " host_choice

    case "$host_choice" in
        1)
            echo ""
            echo "=== IPs ONLY ==="
            local ips=$(echo "$hosts" | sed 's/:[0-9]*$//' | sort -u)
            echo "$ips"
            echo ""
            echo "Total unique IPs: $(echo "$ips" | wc -l)"
            echo ""
            echo "Options:"
            echo "1 - Save IPs to file"
            echo "0 - Back"
            echo ""
            read -p "Select option [0-1]: " ip_choice
            case "$ip_choice" in
                1)
                    read -p "Enter filename: " filename
                    if [[ -n "$filename" ]]; then
                        echo "$ips" > "$filename"
                        echo "IPs saved to $filename"
                    fi
                    read -p "Press Enter to continue..."
                    ;;
                0|*)
                    ;;
            esac
            ;;
        2)
            read -p "Enter filename: " filename
            if [[ -n "$filename" ]]; then
                echo "$hosts" > "$filename"
                echo "Hosts with ports saved to $filename"
            fi
            read -p "Press Enter to continue..."
            ;;
        0|*)
            return
            ;;
    esac
}

search_by_port() {
    echo ""
    read -p "Enter port number: " port_num

    if [[ ! "$port_num" =~ ^[0-9]+$ ]]; then
        echo "Invalid port number."
        read -p "Press Enter to continue..."
        return
    fi

    echo ""
    echo "=== HOSTS WITH PORT $port_num ==="

    local result=$(tr ',' '\n' < "$FILE" \
        | sed 's/^[ \t]*//;s/[ \t]*$//' \
        | tr ';' '\n' \
        | grep -E ":[0-9]+$" \
        | grep ":$port_num$" \
        | sort -u)

    if [[ -z "$result" ]]; then
        echo "No hosts found with port $port_num"
        echo ""
        echo "Options:"
        echo "1 - Save empty result to file"
        echo "0 - Back"
        echo ""
        read -p "Select option [0-1]: " empty_choice
        case "$empty_choice" in
            1)
                read -p "Enter filename: " filename
                if [[ -n "$filename" ]]; then
                    echo "No hosts found with port $port_num" > "$filename"
                    echo "Empty result saved to $filename"
                fi
                read -p "Press Enter to continue..."
                ;;
            0|*)
                ;;
        esac
    else
        echo "$result"
        echo ""
        echo "Total hosts: $(echo "$result" | wc -l)"
        echo ""
        echo "Options:"
        echo "1 - Save results to file"
        echo "0 - Back"
        echo ""
        read -p "Select option [0-1]: " save_choice
        case "$save_choice" in
            1)
                read -p "Enter filename: " filename
                if [[ -n "$filename" ]]; then
                    echo "$result" > "$filename"
                    echo "Port search results saved to $filename"
                fi
                read -p "Press Enter to continue..."
                ;;
            0|*)
                read -p "Press Enter to continue..."
                ;;
        esac
    fi
}

search_by_term() {
    echo ""
    read -p "Enter search term: " search_term

    if [[ -z "$search_term" ]]; then
        echo "Search term cannot be empty."
        read -p "Press Enter to continue..."
        return
    fi

    echo ""
    echo "=== SEARCH RESULTS FOR: $search_term ==="

    local result=$(cut -d ';' -f 1,2 "$FILE" | sed 's/;/ - /' | sed 's/^None - /Info - /' | grep -i "$search_term")

    if [[ -z "$result" ]]; then
        echo "No results found for '$search_term'"
        echo ""
        echo "Options:"
        echo "1 - Save empty result to file"
        echo "0 - Back"
        echo ""
        read -p "Select option [0-1]: " empty_choice
        case "$empty_choice" in
            1)
                read -p "Enter filename: " filename
                if [[ -n "$filename" ]]; then
                    echo "No results found for '$search_term'" > "$filename"
                    echo "Empty result saved to $filename"
                fi
                read -p "Press Enter to continue..."
                ;;
            0|*)
                ;;
        esac
    else
        echo "$result"
        echo ""
        echo "Total results: $(echo "$result" | wc -l)"
        echo ""
        echo "Options:"
        echo "1 - Save results to file"
        echo "0 - Back"
        echo ""
        read -p "Select option [0-1]: " save_choice
        case "$save_choice" in
            1)
                read -p "Enter filename: " filename
                if [[ -n "$filename" ]]; then
                    echo "$result" > "$filename"
                    echo "Search results saved to $filename"
                fi
                read -p "Press Enter to continue..."
                ;;
            0|*)
                read -p "Press Enter to continue..."
                ;;
        esac
    fi
}

show_help() {
    echo "Nessus Vulnerability Parser - v1.0"
    echo ""
    if [[ -f "$FILE" ]]; then
        echo "Found file: $FILE"
    else
        echo "Data file: scan_results_hosts_ports.txt (not found)"
    fi
    echo ""
    echo "COMMANDS:"
    echo "   run                             Process CSV files and create vulnerability database"
    echo "   menu                            Start interactive menu system"
    echo "   analyze                         Show vulnerability statistics and risk assessment"
    echo ""
    echo "GENERAL OPTIONS:"
    echo "   -n, --name <vuln_name>          Search by vulnerability name"
    echo "   -f, --find <term>               Search for specific term"
    echo "   -s, --severity <level>          Filter by severity level (Critical,High,Medium,Low,Info)"
    echo "   -p, --port <number>             Search by port number"
    echo "   -e, --exclude-port              Show IPs only (no ports) [for -i and -p only]"
    echo "   -o, --output <file>             Write to file instead of stdout"
    echo "   -h, --help                      Get help for commands"
    echo "   -v, --version                   Show version number and quit"
    echo ""
    echo "EXAMPLE USAGE:"
    echo "   nespar run                                      # Process CSV files first"
    echo "   nespar menu                                     # Start interactive mode"
    echo "   nespar analyze                                  # Show vulnerability statistics"
    echo "   nespar -n 'SNMP Agent Default Community Name (public)' --exclude-port"
    echo "   nespar --find 'sql'"
    echo "   nespar -p 443 -o output.txt"
    echo "   nespar --severity Info"
    echo ""
}

if [[ "$#" -eq 0 ]]; then
    echo "$(basename $0): try '$(basename $0) --help' for more information"
    exit 1
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        run)
            process_csv_files
            exit 0
            ;;
        menu)
            interactive_menu
            exit 0
            ;;
        analyze)
            analyze_vulnerabilities
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "nespar v1.0"
            exit 0
            ;;
        -f|--find)
            if [[ -z "$2" ]]; then
                echo "Error: --find requires a search term"
                exit 1
            fi
            SEARCH_TERM="$2"
            shift 2
            while [[ "$#" -gt 0 ]]; do
                case "$1" in
                    -o|--output)
                        if [[ -z "$2" ]]; then
                            echo "Error: --output requires a filename"
                            exit 1
                        fi
                        OUTPUT_FILE="$2"
                        shift 2
                        ;;
                    *)
                        echo "Error: Invalid option $1"
                        exit 1
                        ;;
                esac
            done
            result=$(cut -d ';' -f 1,2 "$FILE" | sed 's/;/ - /' | sed 's/^None - /Info - /' | grep -i "$SEARCH_TERM")
            save_output "$result"
            exit 0
            ;;
        -s|--severity)
            if [[ -z "$2" ]]; then
                echo "Error: --severity requires a severity level"
                exit 1
            fi
            SEVERITY="$2"
            if [[ "$SEVERITY" == "Info" ]]; then
                SEVERITY="None"
            fi
            shift 2
            while [[ "$#" -gt 0 ]]; do
                case "$1" in
                    -o|--output)
                        if [[ -z "$2" ]]; then
                            echo "Error: --output requires a filename"
                            exit 1
                        fi
                        OUTPUT_FILE="$2"
                        shift 2
                        ;;
                    *)
                        echo "Error: Invalid option $1"
                        exit 1
                        ;;
                esac
            done
            result=$(grep -i "^$SEVERITY;" "$FILE" | cut -d ';' -f 1,2 | sed 's/;/ - /' | sed 's/^None - /Info - /')
            save_output "$result"
            exit 0
            ;;
        -n|--name)
            if [[ -z "$2" ]]; then
                echo "Error: --name requires a vulnerability name"
                exit 1
            fi
            VULN_NAME="$2"
            shift 2
            while [[ "$#" -gt 0 ]]; do
                case "$1" in
                    -e|--exclude-port)
                        EXCLUDE_PORT=true
                        shift
                        ;;
                    -o|--output)
                        if [[ -z "$2" ]]; then
                            echo "Error: --output requires a filename"
                            exit 1
                        fi
                        OUTPUT_FILE="$2"
                        shift 2
                        ;;
                    *)
                        echo "Error: Invalid option $1"
                        exit 1
                        ;;
                esac
            done

            if [[ "$EXCLUDE_PORT" == true ]]; then
                result=$(grep -F "$VULN_NAME" "$FILE" \
                    | tr ',' '\n' \
                    | sed 's/^[ \t]*//;s/[ \t]*$//' \
                    | tr ';' '\n' \
                    | grep -v "None" \
                    | grep -vF "$VULN_NAME" \
                    | grep -Ev "Critical|Medium|High|Low|None" \
                    | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$" \
                    | sed 's/:[0-9]*$//' \
                    | sort -u)
            else
                result=$(grep -F "$VULN_NAME" "$FILE" \
                    | tr ',' '\n' \
                    | sed 's/^[ \t]*//;s/[ \t]*$//' \
                    | tr ';' '\n' \
                    | grep -v "None" \
                    | grep -vF "$VULN_NAME" \
                    | grep -Ev "Critical|Medium|High|Low|None" \
                    | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$")
            fi
            save_output "$result"
            exit 0
            ;;
        -p|--port)
            if [[ -z "$2" ]]; then
                echo "Error: --port requires a port number"
                exit 1
            fi
            if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                echo "Error: Port must be a valid number"
                exit 1
            fi
            PORT_NUM="$2"
            shift 2
            while [[ "$#" -gt 0 ]]; do
                case "$1" in
                    -e|--exclude-port)
                        EXCLUDE_PORT=true
                        shift
                        ;;
                    -o|--output)
                        if [[ -z "$2" ]]; then
                            echo "Error: --output requires a filename"
                            exit 1
                        fi
                        OUTPUT_FILE="$2"
                        shift 2
                        ;;
                    *)
                        echo "Error: Invalid option $1"
                        exit 1
                        ;;
                esac
            done

            if [[ "$EXCLUDE_PORT" == true ]]; then
                result=$(tr ',' '\n' < "$FILE" \
                    | sed 's/^[ \t]*//;s/[ \t]*$//' \
                    | tr ';' '\n' \
                    | grep -E ":[0-9]+$" \
                    | grep ":$PORT_NUM$" \
                    | sed 's/:[0-9]*$//' \
                    | sort -u)
            else
                result=$(tr ',' '\n' < "$FILE" \
                    | sed 's/^[ \t]*//;s/[ \t]*$//' \
                    | tr ';' '\n' \
                    | grep -E ":[0-9]+$" \
                    | grep ":$PORT_NUM$" \
                    | sort -u)
            fi
            save_output "$result"
            exit 0
            ;;
        *)
            echo "Error: Invalid option $1"
            echo "$(basename $0): try '$(basename $0) --help' for more information"
            exit 1
            ;;
    esac
done

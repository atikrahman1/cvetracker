#!/bin/bash

# Slack webhook URL (replace with your actual URL)
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXXXXXXXXXXXXXXXXXXXXX"

# Log file path
LOG_FILE="script_run.log"

# Function to log the time and date of script execution
log_execution_time() {
    echo "Script run at: $(date)" >> "$LOG_FILE"
}

# Define colors
BLUE='\e[1;34'
RED='\e[1;31'
NC='\e[0m' # No Color

# Function to send Slack notification
send_slack_notification() {
    if [ "$ENABLE_SLACK" = true ]; then
        local cve_id=$1
        local cve_description=$2
        local cvss_score=$3
        local severity=$4
        local product=$5
        local updated_at=$6
        local reference=$7
        local published_at=$8
        local is_exploited=$9
        local is_poc=${10}
        local poc=${11}
                

        # Truncate cve_description to 200 characters
        if [ ${#cve_description} -gt 200 ]; then
            cve_description="${cve_description:0:197}..."  # Truncate and add ellipsis
        fi

        # Format the Slack message
        local read_more_link="https://nvd.nist.gov/vuln/detail/${cve_id}"
        local description_with_link="${cve_description} [<${read_more_link}|Read more>]"
        local color

        if (( $(echo "$cvss_score > 8.0" | bc -l) )); then
            color="#ad0614"  # Red for score > 8.0
        else
            color="#FFD700"  # Yellow for score <= 8.0
        fi

        # Construct the JSON payload
        local payload=$(cat <<EOF
    {
        "attachments": [
            {
                "fallback": "${cve_id} CVE Tracker Alert",
                "author_name": "CVE Tracker Alert",
                "author_icon": "https://ppcl.com/wp-content/uploads/2022/01/PPCL_Icons_CVE_600_Tiny-480x480.png",
                "title": "${cve_id}",
                "title_link": "${read_more_link}",
                "fields": [
                    {
                        "title": "Cvss score",
                        "value": "${cvss_score}",
                        "short": true
                    },
                    {
                        "title": "Last Updated",
                        "value": "${updated_at}",
                        "short": true
                    },
                    {
                        "title": "Severity",
                        "value": "${severity}",
                        "short": true
                    },
                    {
                        "title": "Published at",
                        "value": "${published_at}",
                        "short": true
                    },
                    {
                        "title": "Product",
                        "value": "${product}",
                        "short": true
                    },
                    {
                        "title": "Description",
                        "value": "${description_with_link}",
                        "short": true
                    },
                    {
                        "title": "Exploited wild",
                        "value": "${is_exploited}",
                        "short": true
                    },
                    {
                        "title": "Reference",
                        "value": "${reference}",
                        "short": true
                    },
                    {
                        "title": "Poc",
                        "value": "${poc}",
                        "short": true
                    }
                ],
                "mrkdwn_in": ["pretext"],
                "color": "${color}"
            }
        ]
    }
EOF
)

        # Send the notification
        curl -X POST -H 'Content-type: application/json' --data "${payload}" ${SLACK_WEBHOOK_URL} -s
        echo -e "\e[1;31m$cve_id\e[0m have been found for \e[1;34m$product\e[0m. Notifications sent for new CVEs, and data appended to reported.json."
    else
        echo -e "\e[1;31m$cve_id\e[0m found for the product \e[1;34m$product\e[0m"
    fi
}

# Function to run cvemap and process output
process_cvemap_output() {
    local cvemap_output="$1"

    # Process each CVE and send notification if not already reported
    echo "$cvemap_output" | while IFS= read -r line; do
        cve_id=$(echo "$line" | jq -r '.cve_id')

        # Check if CVE is already reported
        if is_cve_reported "$cve_id"; then
            echo -e "\e[1;31m$cve_id\e[0m is already reported. Skipping notification."
            continue
        fi

        # Extract other fields
        cve_description=$(echo "$line" | jq -r '.cve_description')
        cvss_score=$(echo "$line" | jq -r '.cvss_score')
        severity=$(echo "$line" | jq -r '.severity')
        product=$(echo "$line" | jq -r '.product')
        updated_at=$(echo "$line" | jq -r '.updated_at')
        reference=$(echo "$line" | jq -r '.reference')
        published_at=$(echo "$line" | jq -r '.published_at')
        is_exploited=$(echo "$line" | jq -r '.is_exploited')
        is_poc=$(echo "$line" | jq -r '.is_poc')
        poc=$(echo "$line" | jq -r '.poc')

        # Send Slack notification
        send_slack_notification "$cve_id" "$cve_description" "$cvss_score" "$severity" "$product" "$updated_at" "$reference" $published_at $is_exploited $is_poc $poc

        # Append the new CVE to reported.json
        append_cve_to_reported "$line"

    done
}

# Function to check if a CVE is already in reported.json
is_cve_reported() {
    local cve_id=$1
    if jq -e --arg cve_id "$cve_id" '.[] | select(.cve_id == $cve_id)' reported.json > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to append CVE to reported.json
append_cve_to_reported() {
    local cve_data=$1

    # Check if the file exists and is non-empty
    if [ ! -s reported.json ]; then
        # Initialize the JSON array if the file is empty or doesn't exist
        echo "[$cve_data]" > reported.json
    else
        # Append the new CVE data to the JSON array
        # Remove the last `]`, add the new CVE, and close the array again
        jq '.' reported.json &>/dev/null  # Validate if the file is a valid JSON
        if [ $? -eq 0 ]; then
            jq '.' reported.json | sed '$ s/]$//' > temp.json && mv temp.json reported.json
            echo ",$cve_data]" >> reported.json
        else
            echo "Error: reported.json is not a valid JSON file. Please check the file format."
            exit 1
        fi
    fi
}


# Function to process CPE file using xargs
process_cpe_file() {
    local file=$1

    # Process each CPE in the file using xargs
    cat "$file" | xargs -I {} cvemap -c {} -j -silent | jq -c '.[] | {
        cve_id: .cve_id,
        cve_description: (if .cve_description | length > 200 then .cve_description[:197] + "..." else .cve_description end),
        severity: .severity,
        cvss_score: .cvss_metrics.cvss31.score,
        product: .cpe.product,
        published_at: .published_at,
        updated_at: .updated_at,
        reference: (.reference[0] // ""),
        is_exploited: .is_exploited,
        is_poc: .is_poc,
        poc: (.poc[0].url)
    }' | while IFS= read -r output; do
        process_cvemap_output "$output"
    done
}


# Check if the correct number of arguments are provided
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 -p <product_name> or $0 -c <cpe_name> or $0 -fp <product_file> or $0 -fc <cpe_file> [-dn]"
    exit 1
fi

# Default to Slack notifications enabled
ENABLE_SLACK=true

# Extract arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -p|-c|-fp|-fc)
            flag=$1
            value=$2
            shift 2
            ;;
        -dn)
            ENABLE_SLACK=false
            shift
            ;;
        *)
            echo "Error: Invalid argument."
            exit 1
            ;;
    esac
done

# Log the time and date of script execution
log_execution_time

# Validate flags and run accordingly
case "$flag" in
    -p|-c)
        process_cpe_file "$value"
        ;;
    -fp)
        process_cpe_file "$value"
        ;;
    -fc)
        process_cpe_file "$value"
        ;;
    *)
        echo "Error: Invalid flag. Use -p for product name, -c for CPE name, -fp for product file, or -fc for CPE file."
        exit 1
        ;;
esac

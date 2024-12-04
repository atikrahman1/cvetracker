
# CVE Tracker Script  

This **CVE Tracker** is a wrapper script designed to automate the detection, tracking, and reporting of Common Vulnerabilities and Exposures (CVEs) for specific products or Common Platform Enumerations (CPEs). 
The script leverages the **`cvemap`** tool to fetch vulnerability information from various sources. It processes the results, sends notifications to Slack, and logs all relevant details in a JSON file (`reported.json`) to avoid duplicate reports.

With this script, security teams can:
- Automate CVE discovery based on product names or CPEs.
- Get real-time Slack notifications for critical vulnerabilities.
- Track previously reported vulnerabilities in a centralized JSON file.
- Simplify repetitive security tasks and integrate with other monitoring tools.

This script is especially useful for DevSecOps teams, security researchers, and system administrators who need a streamlined way to monitor vulnerabilities in their infrastructure or applications.

## Features  

- **Slack Notifications**: Sends alerts for new CVEs with details such as severity, CVSS score, and references.  
- **CVE Logging**: Tracks all CVE notifications in a JSON file (`reported.json`).  
- **Execution Logging**: Logs the time and date of each script execution in `script_run.log`.  
- **Product and CPE Input**: Supports single products/CPEs or batch processing from files.  
- **Colorized Output**: Displays CVE ID in red and product name in blue.  
- **Slack Notification Toggle**: Allows enabling or disabling Slack notifications via the `-dn` flag.

![Alt text](https://raw.githubusercontent.com/atikrahman1/cvetracker/refs/heads/main/Slack-notification-preview.png)


## Prerequisites  

- **cveMap**: Ensure [cveMap](https://github.com/projectdiscovery/cvemap) is installed and accessible from the terminal.
- **jq**: JSON processor for parsing CVE data (`jq` should be installed).  
- **curl**: For sending Slack notifications.  

## Configuration  

1. Replace the placeholder Slack webhook URL in the script with your actual webhook URL:  

    ```bash  
    SLACK_WEBHOOK_URL="https://hooks.slack.com/services/xxxxxxxxxxxx"  
    ```  

## Usage  

```bash  
./cve_tracker.sh [OPTIONS] [ARGUMENTS] [-dn]  
```  

### Options  

- `-p <product_name>`: Search for CVEs related to a single product name.  
- `-c <cpe_name>`: Search for CVEs related to a single CPE (Common Platform Enumeration) name.  
- `-fp <product_file>`: Search for CVEs related to a list of product names from a file.  
- `-fc <cpe_file>`: Search for CVEs related to a list of CPEs from a file.  
- `-dn`: Disable Slack notifications for the current run (notifications are enabled by default).  

### Examples  

1. **Search for CVEs by product name and send Slack notifications**:  
    ```bash  
    ./cve_tracker.sh -p "example_product"  
    ```  

2. **Search for CVEs by CPE and disable Slack notifications**:  
    ```bash  
    ./cve_tracker.sh -c "cpe:/o:vendor:example_product" -dn  
    ```  

3. **Process a list of products from a file and send Slack notifications**:  
    ```bash  
    ./cve_tracker.sh -fp product_list.txt  
    ```  

4. **Process a list of CPEs from a file and disable Slack notifications**:  
    ```bash  
    ./cve_tracker.sh -fc cpe_list.txt -dn  
    ```  

## Output  

- **Slack Notifications**:  
  - Displays CVE details in a Slack channel.  
  - Highlights critical CVEs (CVSS > 8.0) in red and others in yellow.  

- **Console Output**:  
  - Displays colorized output for CVE ID (red) and product name (blue).  

- **Log Files**:  
  - `script_run.log`: Records the date and time of each script execution.  
  - `reported.json`: Appends new CVEs with details for future reference.  

## JSON Structure in `reported.json`  

```json  
{
    "cve_id": "CVE-YYYY-NNNN",
    "cve_description": "Brief description of the vulnerability...",
    "severity": "Critical",
    "cvss_score": "9.8",
    "product": "example_product",
    "published_at": "2024-12-01",
    "updated_at": "2024-12-02",
    "reference": "https://example.com/cve-details",
    "is_exploited": "true",
    "is_poc": "true",
    "poc": "https://example.com/poc-details"
}
```  

## Known Issues  

- The script currently does not validate network connectivity for the Slack webhook. Ensure that your network permits outgoing connections to Slack.  
- The script expects valid JSON formatting for `reported.json`. If the file is corrupted, an error will be displayed, and execution will terminate.  

## Future Improvements  

- Add email notifications for CVE alerts.  
- Implement support for additional CVE tracking tools.  
- Add retry logic for Slack notifications in case of network failures.

- ## Contact Me  

Feel free to reach out if you have any questions, feedback, or collaboration opportunities:

- **LinkedIn**: [Atikqur Rahman](https://www.linkedin.com/in/atikqur-rahman/)  
- **X (formerly Twitter)**: [@atikqur007](https://x.com/atikqur007)  


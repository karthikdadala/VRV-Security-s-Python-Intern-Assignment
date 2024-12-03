import csv
from collections import defaultdict, Counter

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Log file name
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

def parse_log_file(file_name):
    """
    Parses the log file and extracts required data.
    Returns:
        logs (list): Parsed log entries as dictionaries.
    """
    logs = []
    with open(file_name, 'r') as file:
        for line in file:
            parts = line.split(" ")
            ip_address = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            message = " ".join(parts[9:]).strip()
            logs.append({
                "ip": ip_address,
                "endpoint": endpoint,
                "status": status_code,
                "message": message,
            })
    return logs

def count_requests_per_ip(logs):
    """
    Counts the number of requests per IP address.
    Returns:
        Counter: Dictionary of IP addresses and request counts.
    """
    ip_counts = Counter(log["ip"] for log in logs)
    return ip_counts

def find_most_accessed_endpoint(logs):
    """
    Identifies the most frequently accessed endpoint.
    Returns:
        tuple: The most accessed endpoint and its count.
    """
    endpoint_counts = Counter(log["endpoint"] for log in logs)
    most_accessed = endpoint_counts.most_common(1)[0]
    return most_accessed

def detect_suspicious_activity(logs, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Detects IPs with suspicious failed login attempts.
    Returns:
        dict: IPs flagged for suspicious activity with their failed login counts.
    """
    failed_attempts = Counter(
        log["ip"] for log in logs if log["status"] == "401" or "Invalid credentials" in log["message"]
    )
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips

def save_results_to_csv(ip_requests, most_accessed, suspicious_activity, file_name):
    """
    Saves analysis results to a CSV file.
    """
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])
        
        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        
        # Write suspicious activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    logs = parse_log_file(LOG_FILE)

    # Analyze logs
    ip_requests = count_requests_per_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_activity, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()

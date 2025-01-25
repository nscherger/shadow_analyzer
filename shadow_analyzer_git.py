import os          
import csv         
from datetime import datetime

def analyze_shadow_file(input_path="/etc/shadow", output_path="shadow_analysis.csv"):
    """
    Analyzes the Linux shadow file for security issues and outputs findings to CSV.
    Checks for:
    - Empty passwords
    - Password age issues
    - Accounts with no password expiry
    - Recently changed passwords
    """
    try:
        # Check if running as root (required for shadow file)
        if os.geteuid() != 0:    
            raise PermissionError("This script must be run as root to access /etc/shadow")
            
        security_issues = []      # Initialize empty list to store findings
        
        print("Attempting to read shadow file...")
        
        with open(input_path, 'r') as shadow_file:    # Open file for reading
            for line in shadow_file:
                try:
                    # Parse each line of the shadow file
                    parts = line.strip().split(':')    # Split line into parts at colons
                    
                    if len(parts) < 9:
                        print(f"Skipping malformed line: {line.strip()}")
                        continue
                    
                    username = parts[0]
                    password_field = parts[1]
                    last_changed = parts[2]
                    min_age = parts[3]
                    max_age = parts[4]
                    warning_period = parts[5]
                    
                    issues = []
                    
                    # Check for empty/invalid passwords
                    if password_field in ['', '*', '!', '!!']:
                        issues.append("No password set")
                    elif password_field == 'x':    
                        issues.append("Password stored in /etc/shadow")
                    
                    # Check password age if dates are set
                    if last_changed:   
                        try:
                            last_change_date = int(last_changed)
                            
                            # Calculate days since password change
                            days_since_change = (datetime.now() - 
                                datetime.fromtimestamp(last_change_date * 86400)).days
                            
                            if max_age and int(max_age) > 0:   
                                if days_since_change > int(max_age):
                                    issues.append(f"Password expired {days_since_change - int(max_age)} days ago")
                            else:
                                issues.append("No password expiry set")
                                
                            if days_since_change < 1:
                                issues.append("Password changed today - verify if authorized")
                        except ValueError:
                            issues.append("Invalid date format in password age field")
                    
                    # If issues were found, add them to our results
                    if issues:  
                        security_issues.append({
                            'username': username,
                            'issues': '; '.join(issues),
                            'last_changed': last_changed,
                            'max_age': max_age,
                            'warning_period': warning_period
                        })
                        
                except Exception as e:
                    print(f"Error processing line for user: {parts[0] if len(parts) > 0 else 'unknown'}")
                    print(f"Error details: {str(e)}")
                    continue

        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['username', 'issues', 'last_changed', 'max_age', 'warning_period']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for issue in security_issues:
                writer.writerow(issue)
                
        print(f"\nAnalysis complete. Found {len(security_issues)} potential security issues.")
        print(f"Results written to {output_path}")
        
    except PermissionError as e:
        print(f"Permission error: {e}")
        print("Please run the script with sudo:")
        print("sudo python3 shadow_analyzer.py")
    except FileNotFoundError:
        print(f"Error: Could not find shadow file at {input_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Script entry point
if __name__ == "__main__":
    analyze_shadow_file()
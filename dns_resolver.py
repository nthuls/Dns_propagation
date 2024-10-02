import argparse
import json
import sys
from datetime import datetime
import yaml
import os
import psycopg2
import mysql.connector
import hashlib
import logging
import smtplib
import requests
from prettytable import PrettyTable, ALL
from dns import resolver
from dotenv import load_dotenv
from email.mime.text import MIMEText

# Load environment variables from .env file
load_dotenv()

version = "0.0.8"

# Define the log paths
LOG_DIR_PATH = "/var/log/domain"
DNS_LOG_FILE_PATH = os.path.join(LOG_DIR_PATH, "dns_results.log")
ERROR_LOG_FILE_PATH = os.path.join(LOG_DIR_PATH, "error.log")

# Ensure log directory and file exist, and set appropriate permissions
def setup_logging():
    try:
        # Ensure the log directory exists
        if not os.path.exists(LOG_DIR_PATH):
            os.makedirs(LOG_DIR_PATH)
            print(f"Directory {LOG_DIR_PATH} created.")

        # Ensure DNS log file exists
        if not os.path.exists(DNS_LOG_FILE_PATH):
            with open(DNS_LOG_FILE_PATH, "w") as log_file:
                log_file.write("DNS Results Log\n")
            print(f"DNS log file {DNS_LOG_FILE_PATH} created.")

        # Ensure error log file exists
        if not os.path.exists(ERROR_LOG_FILE_PATH):
            with open(ERROR_LOG_FILE_PATH, "w") as log_file:
                log_file.write("Error Log\n")
            print(f"Error log file {ERROR_LOG_FILE_PATH} created.")

        # Set file permissions for DNS and error logs to rw-r--r--
        os.chmod(DNS_LOG_FILE_PATH, 0o644)
        os.chmod(ERROR_LOG_FILE_PATH, 0o644)
        print(f"Permissions set on {DNS_LOG_FILE_PATH} and {ERROR_LOG_FILE_PATH} (rw-r--r--)")

    except OSError as e:
        print(f"Error creating or setting permissions for log files: {e}")

    # Set up error logger
    error_logger = logging.getLogger("error_logger")
    error_logger.setLevel(logging.ERROR)
    debug_logger = logging.getLogger("debug_logger")
    debug_logger.setLevel(logging.DEBUG)

    # Set up file handler for error log
    error_file_handler = logging.FileHandler(ERROR_LOG_FILE_PATH)
    error_file_handler.setLevel(logging.ERROR)
    error_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    error_logger.addHandler(error_file_handler)

    # Set up file handler for debug log (in error.log)
    debug_file_handler = logging.FileHandler(ERROR_LOG_FILE_PATH)
    debug_file_handler.setLevel(logging.DEBUG)
    debug_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    debug_logger.addHandler(debug_file_handler)

    # Set up DNS results logger
    dns_logger = logging.getLogger("dns_logger")
    dns_logger.setLevel(logging.INFO)

    # Set up file handler for DNS results log
    dns_file_handler = logging.FileHandler(DNS_LOG_FILE_PATH)
    dns_file_handler.setLevel(logging.INFO)
    dns_file_handler.setFormatter(logging.Formatter('%(message)s'))
    dns_logger.addHandler(dns_file_handler)

    return dns_logger, error_logger, debug_logger


# Static DNS server data with country and owner information
default_dns = [
    {"ipv4": "8.8.8.8", "owner": "google", "country": "USA"},
    {"ipv4": "1.1.1.1", "owner": "cloudflare", "country": "USA"},
    {"ipv4": "9.9.9.9", "owner": "quad9", "country": "Switzerland"},
    {"ipv4": "208.67.222.222", "owner": "opendns", "country": "USA"}
]


# Connect to the database (PostgreSQL or MariaDB) based on .env configuration
def connect_db(debug_logger, error_logger):
    db_type = os.getenv("DB_TYPE")
    if os.getenv("USE_DB") == "false":
        return None
    try:
        if db_type == "postgresql":
            conn = psycopg2.connect(
                dbname=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT")
            )
            debug_logger.debug("Connected to PostgreSQL")
            return conn
        elif db_type == "mariadb":
            conn = mysql.connector.connect(
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                database=os.getenv("DB_NAME")
            )
            debug_logger.debug("Connected to MariaDB")
            return conn
        else:
            error_logger.error("No valid DB_TYPE set.")
            return None
    except Exception as e:
        error_logger.error(f"Error connecting to database: {e}")
        return None

# Create tables for storing results and hashes
def create_tables(conn):
    cursor = conn.cursor()
    # Create DNS results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_results (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255),
            record_type VARCHAR(10),
            server VARCHAR(255),
            location VARCHAR(255),
            response TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Create DNS hashes table for change detection
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_hashes (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255),
            record_type VARCHAR(10),
            hash VARCHAR(255),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()


# DNS query function
def query_dns(domain, record_type, dns_servers=None, debug_logger=None, error_logger=None):
    resolver_obj = resolver.Resolver()
    if dns_servers:
        resolver_obj.nameservers = dns_servers

    # Use root logger if no debug_logger is passed
    if debug_logger is None:
        debug_logger = logging.getLogger()
        debug_logger.setLevel(logging.DEBUG)

    if error_logger is None:
        error_logger = logging.getLogger()
        error_logger.setLevel(logging.ERROR)

    debug_logger.debug(f"Starting DNS query for {domain} with type {record_type} on servers {dns_servers}")

    try:
        answers = resolver_obj.resolve(domain, record_type.upper())  # Ensure record type is case insensitive
        results = [answer.to_text() for answer in answers]
        debug_logger.debug(f"Received DNS answers: {results}")
        return results
    except resolver.NoAnswer:
        error_message = f"No answer for {domain} {record_type}"
        error_logger.error(error_message)
        return [error_message]
    except resolver.NXDOMAIN:
        error_message = f"Domain {domain} does not exist"
        error_logger.error(error_message)
        return [error_message]
    except resolver.Timeout:
        error_message = f"Timeout querying {domain} {record_type}"
        error_logger.error(error_message)
        return [error_message]
    except Exception as e:
        error_message = f"Error querying {domain} {record_type}: {e}"
        error_logger.error(error_message)
        return [error_message]


def parse_dns_queries_file(file_path):
    """
    Parses a file containing DNS queries.
    The file should contain lines with the format:
    <record_type> <domain_or_ip>

    Returns a list of dictionaries with 'record_type' and 'domain' keys.
    """
    dns_queries = []

    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Skip empty lines or lines that are comments
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) == 2:
                        record_type, domain = parts
                        dns_queries.append({
                            'record_type': record_type.upper(),  # Ensure record type is uppercase
                            'domain': domain
                        })
                    else:
                        print(f"Skipping invalid line: {line}")
        return dns_queries

    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return []


# Hash DNS results for change detection
def hash_dns_results(results):
    return hashlib.sha256(str(results).encode('utf-8')).hexdigest()

# Function to get location based on IP address
def get_location_from_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return data.get("country", "Unknown Location")
        else:
            return "Unknown Location"
    except Exception as e:
        print(f"Error fetching location for IP {ip}: {e}")
        return "Unknown Location"

# Compare current results with the last stored hash
def detect_changes(conn, domain, record_type, current_hash):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT hash FROM dns_hashes WHERE domain=%s AND record_type=%s ORDER BY timestamp DESC LIMIT 1;
    """, (domain, record_type))
    result = cursor.fetchone()

    if result:
        last_hash = result[0]
        if last_hash == current_hash:
            return False  # No change detected
    # Insert the new hash
    cursor.execute("""
        INSERT INTO dns_hashes (domain, record_type, hash) VALUES (%s, %s, %s);
    """, (domain, record_type, current_hash))
    conn.commit()
    return True  # Change detected


# Function to send notifications to Discord (if enabled in .env)
def notify_discord_embedded(message, table_str):
    # Check if Discord notifications are enabled in the .env file
    if os.getenv("ENABLE_DISCORD_NOTIFICATIONS", "false").lower() == "true":
        webhook_urls = os.getenv("DISCORD_WEBHOOK", "").split(",")  # Handle multiple webhooks

        if webhook_urls:
            for webhook_url in webhook_urls:
                webhook_url = webhook_url.strip()  # Remove any surrounding whitespace
                if webhook_url:  # Ensure the URL is not empty
                    embed_data = {
                        "content": f"Alert!!! Change Detected {message}",
                        "embeds": [
                            {
                                "title": "DNS Query Results",
                                "description": f"```{table_str}```",  # Embed the pretty table as code
                                "color": 16711680  # Optional: color in red for alerts
                            }
                        ]
                    }

                    try:
                        response = requests.post(webhook_url, json=embed_data)
                        if response.status_code != 204:
                            print(f"Error sending Discord notification to {webhook_url}: {response.status_code}")
                    except Exception as e:
                        print(f"Failed to send Discord notification to {webhook_url}: {e}")
                else:
                    print("Empty webhook URL, skipping.")
        else:
            print("No Discord webhook URL set.")
    else:
        print("Discord notifications are disabled.")


# Insert results into the database and log results regardless of the DB condition
def process_results(args_dict, server, result, conn, dns_logger, debug_logger, error_logger):
    try:
        # Log the DNS results regardless of DB availability
        debug_logger.debug(f"Processing DNS results for {args_dict['domain']} ({args_dict['record_type']})")

        # Query the location of the DNS server
        server_ip = server['ipv4']
        server_location = get_location_from_ip(server_ip)

        log_dns_results_as_json(args_dict["domain"], args_dict["record_type"], server_ip, server_location, result,
                                dns_logger)

        if conn:
            debug_logger.debug(f"Inserting results into the database for {args_dict['domain']}")
            insert_dns_results(conn, args_dict["domain"], args_dict["record_type"], server_ip, server_location,
                               str(result))

            # Hash-based change detection
            current_hash = hash_dns_results(result)
            if detect_changes(conn, args_dict["domain"], args_dict["record_type"], current_hash):
                # Enrich the change_message with more information
                change_message = (f"DNS propagation change detected for {args_dict['domain']} "
                                  f"(Record Type: {args_dict['record_type']}) on server {server_ip}. "
                                  f"Location: {server_location}. Answer: {', '.join(result)}.")

                # Generate the pretty table string
                formatted_table = print_pretty_table(
                    [{"server": server_ip, "location": server_location, "answer": result}]
                )

                debug_logger.debug(f"Sending notification for DNS change detected on {args_dict['domain']}")

                # Notify via Discord if enabled
                notify_discord_embedded(formatted_table)

                # Notify via email if enabled
                notify_email(change_message)
        else:
            debug_logger.debug(f"Logging DNS result to file (no DB connection)")
            log_dns_results_as_json(args_dict["domain"], args_dict["record_type"], server_ip, server_location, result,
                                    dns_logger)

    except Exception as e:
        error_logger.error(f"Error processing results for {args_dict['domain']}: {e}")


# Function to send email notifications (if enabled in .env)
def notify_email(message, debug_logger, error_logger):
    # Check if email notifications are enabled in the .env file
    if os.getenv("ENABLE_EMAIL_NOTIFICATIONS", "false").lower() == "true":
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = os.getenv("SMTP_PORT", 587)
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        to_email = os.getenv("ALERT_EMAILS", "").split(",")

        if smtp_server and smtp_user and smtp_password and to_email:
            msg = MIMEText(message)
            msg['Subject'] = 'DNS Propagation Alert'
            msg['From'] = smtp_user
            msg['To'] = to_email.strip()  # Strip whitespace from email addresses
            try:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [to_email.strip()], msg.as_string())
                server.quit()
                print(f"Alert sent to {to_email}")
            except Exception as e:
                error_logger.error(f"Failed to send email: {e}")
        else:
            print("SMTP configuration not set.")
    else:
        debug_logger.debug("Email notifications are disabled.")


def parse_yaml(file_path):
    """
    Generator that yields each server entry from the YAML file one at a time.
    """
    try:
        with open(file_path, 'r') as file:
            # Load and yield each server entry one at a time
            data = yaml.safe_load(file)  # This loads the whole document, consider streaming if extremely large files
            for server in data:
                yield server
    except FileNotFoundError:
        print(f"YAML file {file_path} not found")
        raise
    except yaml.YAMLError as exc:
        print(f"Error parsing YAML file: {exc}")
        raise


# Filter DNS servers by country or owner
def filter_servers(servers, country=None, owner=None):
    filtered_servers = []
    for server in servers:
        if (country is None or server['country'] in country) and (owner is None or server['owner'] in owner):
            filtered_servers.append(server)
    return filtered_servers


# Insert DNS results into the database
def insert_dns_results(conn, domain, record_type, server, location, response):
    cursor = conn.cursor()
    # Fallback to ipinfo.io if location is unknown
    if location == "Unknown Location":
        location = get_location_from_ip(server)

    cursor.execute("""
        INSERT INTO dns_results (domain, record_type, server, country, response)
        VALUES (%s, %s, %s, %s, %s);
    """, (domain, record_type, server, location, response))
    conn.commit()


# Log DNS results to file
def log_dns_results(domain, record_type, server, location, response, dns_logger):
    log_entry = f"Domain: {domain}, Record Type: {record_type}, Server: {server}, Location: {location}, Response: {response}"
    dns_logger.info(log_entry)


# Log DNS results as JSON to file
def log_dns_results_as_json(domain, record_type, results, log_file_path):
    # Process each result to ensure proper location handling
    for result in results:
        server_ip = result['server']
        server_location = result['location']

        # Fallback to ipinfo.io if location is unknown
        if server_location == "Unknown Location":
            server_location = get_location_from_ip(server_ip)

        data = {
            "domain": domain,
            "record_type": record_type,
            "server": server_ip,
            "country": server_location,
            "answer": result['answer'],
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # Add timestamp
            "source": "DNS propagation checker"  # You can add a source or context if needed
        }

        # Log as JSON
        with open(log_file_path, 'a') as log_file:
            json.dump(data, log_file)
            log_file.write('\n')  # Ensure each JSON object is on a new line



def read_dns_servers(file_path):
    """
    Reads a flat text file with DNS server IPs, one per line.
    """
    try:
        with open(file_path, 'r') as file:
            dns_servers = [line.strip() for line in file if line.strip()]
        return dns_servers
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)

# Print results in a pretty table
# Function to print a pretty table, handles both DNS query results and default DNS list
def print_pretty_table(results, expected=None):
    x = PrettyTable()

    # Check if the results contain DNS query answers or are the default DNS list
    if 'answer' in results[0]:
        # This block is for DNS query results
        x.field_names = ["Server", "Country", "Answer"]
        for result in results:
            answers = []
            for r in result['answer']:
                # Ensure we handle strings and DNS objects separately
                if isinstance(r, str):
                    tmp_string = r  # Handle errors or string results directly
                else:
                    tmp_string = r.to_text()  # Convert DNS object to string

                # Apply coloring based on expected result, errors, or timeouts
                if expected and tmp_string in expected:
                    tmp_string = '\033[92m' + tmp_string + '\033[0m'  # Green for expected match
                elif expected and tmp_string not in expected:
                    tmp_string = '\033[91m' + tmp_string + '\033[0m'  # Red for unexpected result
                elif tmp_string == "timed out":
                    tmp_string = '\033[91m' + "timed out" + '\033[0m'  # Red for timeout
                else:
                    tmp_string = '\033[92m' + tmp_string + '\033[0m'  # Green for valid result

                answers.append(tmp_string)

            result_string = "\n".join(answers)

            # Check if result['server'] is a dictionary or string
            if isinstance(result['server'], dict):
                server_ip = result['server'].get('ipv4', 'Unknown IP')
                server_location = result['server'].get('country', 'Unknown Location')
            else:
                server_ip = result['server']
                server_location = get_location_from_ip(server_ip)

            x.add_row([server_ip, server_location, result_string])

        x._max_width = {"Answer": 70}
        x.align["Answer"] = "l"
        x.hrules = ALL
        print(x)

    else:
        # This block is for default DNS server list (e.g., in show-default)
        x.field_names = ["Server", "Owner", "Country"]
        for result in results:
            x.add_row([result['ipv4'], result['owner'], result['country']])

        x.align["Server"] = "l"
        x.align["Owner"] = "l"
        x.align["Country"] = "l"
        x.hrules = ALL
        print(x)

    return str(x)

# Helper function to format the table results as text for notifications
def format_pretty_table_for_notification(results):
    table_str = "Server\tCountry\tAnswer\n"
    table_str += "-" * 40 + "\n"

    for result in results:
        server_ip = result['server']
        country = result['country']  # Use 'country' instead of 'location'
        answers = "\n".join(result['answer'])
        table_str += f"{server_ip}\t{country}\t{answers}\n"

    return table_str

# Check if the results match the expected value
def check_expected_result(results, expected_value):
    for result in results:
        if isinstance(result['answer'], list) and expected_value in result['answer']:
            return True
    return False


# Main function to handle DNS propagation checks and arguments
def main():
    dns_logger, error_logger, debug_logger = setup_logging()
    debug_logger.debug("Parsing command-line arguments")

    dns_servers = []
    args_dict = {'json': False, 'yaml': False, 'simple': False, 'debug': False, 'dnslist': None, 'random': None,
                 'country': None, 'owner': None, 'expected': None, 'server': None, 'custom_list': None,
                 'show_default': False}

    parser = argparse.ArgumentParser()

    # Add optional arguments
    parser.add_argument("--json", action="store_true", help="Print JSON output instead of a human-readable table.")
    parser.add_argument("--yaml", action="store_true", help="Print YAML output instead of a human-readable table.")
    parser.add_argument("--show-default", action="store_true", help="Show default DNS servers.")
    parser.add_argument("--version", action="store_true", help="Print version information.")
    parser.add_argument("--random", type=int, help="Select N random DNS servers to query.")
    parser.add_argument("--country", type=str, action="append", help="Filter DNS servers by country.")
    parser.add_argument("--owner", type=str, action="append", help="Filter DNS servers by owner.")
    parser.add_argument("--expected", type=str, help="Expected DNS result.")
    parser.add_argument("--server", type=str, action="append", help="Add specific DNS servers to query.")
    parser.add_argument("--custom_list", type=str, help="Custom YAML-formatted DNS server list.")
    parser.add_argument("--file", type=str, help="File containing DNS queries to process.")
    parser.add_argument("--dns_list", help="Path to a flat text file of DNS servers.")
    parser.add_argument("record_type", metavar="TYPE", type=str, nargs="?", help="Type of DNS record to check.")
    parser.add_argument("domain", metavar="DOMAIN", type=str, nargs="?", help="Domain name to check.")

    # Parse arguments
    args = parser.parse_args()
    args_dict.update(vars(args))
    debug_logger.debug(f"Arguments parsed: {args_dict}") # Log parsed arguments for debugging

    # Print version and exit if the --version flag is used
    if args_dict["version"]:
        debug_logger.debug("Version requested.")
        print(f"DNS Propagation Checker Version {version}")
        sys.exit(0)

    #handles default argument
    if args_dict["show_default"]:
        debug_logger.debug("Default DNS server list requested.")
        if args_dict["yaml"]:
            print(yaml.dump(default_dns))
        else:
            print(default_dns)
            print_pretty_table(default_dns)
        exit(0)

        # Validate that either domain and record_type OR --file is provided
    if not args_dict["file"] and (not args_dict["domain"] or not args_dict["record_type"]):
        print("You must specify a record type and domain or provide a file with queries.")
        sys.exit(1)

    debug_logger.debug("Setting up DNS servers")
    dns_servers = []
    if args.custom_list:
        try:
            for server in parse_yaml(args.custom_list):
                if 'ipv4' in server:
                    dns_servers.append(server)
                    debug_logger.debug(f"Added server from YAML: {server}")
                else:
                    error_logger.error("Missing 'ipv4' key in server entry.")
        except Exception as e:
            error_logger.error(f"Error processing YAML file: {e}")
            sys.exit(1)
    elif args.dns_list:
        try:
            for server_ip in read_dns_servers(args.dns_list):
                dns_servers.append({'ipv4': server_ip, 'country': 'Unknown'})  # Country unknown in flat file
                debug_logger.debug(f"Added server from flat file: {server_ip}")
        except Exception as e:
            error_logger.error(f"Error processing DNS server list file: {e}")
            sys.exit(1)
    else:
        dns_servers = default_dns  # Use the default DNS servers if no custom list is provided
        debug_logger.debug("Using default DNS servers.")

    results = []
    for server in dns_servers:
        server_ip = server['ipv4']
        country = server.get('country', 'Unknown')
        answers = query_dns(args.domain, args.record_type, [server_ip], debug_logger=debug_logger, error_logger=error_logger)
        results.append({'server': server_ip, 'country': country, 'answer': answers})


    # Check for required arguments when not using a file
    if not args_dict["file"] and (not args_dict["domain"] or not args_dict["record_type"]):
        print("You must specify a record type and domain or provide a file with queries.")
        sys.exit(1)

    # Filter DNS servers by country/owner
    if args_dict["country"] or args_dict["owner"]:
        dns_servers = filter_servers(dns_servers, args_dict["country"], args_dict["owner"])

    # Connect to the database if enabled
    conn = None
    if os.getenv("USE_DB") == "true":
        conn = connect_db(debug_logger, error_logger)
        create_tables(conn)


    # Run checks for domains from a file if provided
    if args_dict["file"]:
        dns_queries = parse_dns_queries_file(args_dict["file"])
        for query in dns_queries:
            record_type = query['record_type']
            domain = query['domain']

            results = []
            for server in dns_servers:
                server_ip = server['ipv4']
                server_location = get_location_from_ip(server_ip)  # Fetching location using IP information service
                answers = query_dns(domain, record_type, [server_ip], debug_logger=debug_logger,
                                    error_logger=error_logger)
                results.append({'server': server_ip, 'country': server_location, 'answer': answers})

                # Hash the DNS results to detect changes
                current_hash = hash_dns_results(results)

                # Check if the hash already exists in the database (if connected)
                if conn:  # Ensure database connection exists
                    if not detect_changes(conn, domain, record_type, current_hash):
                        # If no changes detected, skip the notification and proceed to the next query
                        debug_logger.debug(f"No changes detected for {domain} ({record_type}). Skipping notifications.")
                        continue

                # Process the results if a new hash is detected or no database is in use
                process_results({'domain': domain, 'record_type': record_type}, server, answers, conn, dns_logger,
                                debug_logger, error_logger)

            formatted_results = format_pretty_table_for_notification(results)

            # After processing all results for a domain, check if results should be printed or saved
            if args_dict["json"]:
                print(json.dumps(results, indent=4))
            elif args_dict["yaml"]:
                print(yaml.dump(results))
            else:
                if os.getenv("VISUALIZE_OUTPUT", "true").lower() == "true":
                    print_pretty_table(results)
                else:
                    print("Output suppressed based on VISUALIZE_OUTPUT setting.")

            # Only notify if a new hash was detected and stored
            if conn:  # If database is used, notify only if changes are detected
                if detect_changes(conn, domain, record_type, current_hash):
                    notify_discord_embedded(f"DNS query results for {domain}", formatted_results)
                    notify_email(f"DNS query results for {domain}: {formatted_results}", debug_logger, error_logger)
            else:
                # Notify without change detection if no database is in use
                notify_discord_embedded(f"DNS query results for {domain}", formatted_results)
                notify_email(f"DNS query results for {domain}: {formatted_results}", debug_logger, error_logger)

        sys.exit(0)  # Exit after processing all queries from the file

    # Run DNS query for the specified domain and record type
    results = []
    for server in dns_servers:
        try:
            server_ip = server['ipv4']
            server_location = server['country'] if server['country'] != "Unknown Location" else get_location_from_ip(
                server_ip)
        except KeyError:
            print("Missing 'ipv4' key in DNS server entry:", server)
            continue  # Skip to the next server if 'ipv4' key is missing

        result = query_dns(args_dict["domain"], args_dict["record_type"], dns_servers=[server['ipv4']])

        # Always process and log the results
        process_results(args_dict, server, result, conn, dns_logger, debug_logger, error_logger)

        # results.append({"server": server['ipv4'], "location": server['country'], "answer": result})
        results.append({"server": server_ip, "location": server_location, "answer": result})


        # Insert results into the database
        if conn:
            insert_dns_results(conn, args_dict["domain"], args_dict["record_type"], server['ipv4'], server['country'],
                               str(result))
            # Hash-based change detection
            current_hash = hash_dns_results(result)
            if detect_changes(conn, args_dict["domain"], args_dict["record_type"], current_hash):                # Trigger notifications if a change is detected
                change_message = f"DNS propagation change detected for {args.domain} (Record Type: {args.record_type})."
                formatted_table = format_pretty_table_for_notification([{"server": server_ip, "location": server_location, "answer": result}])

                notify_discord_embedded(change_message, formatted_table)
                notify_email(change_message, error_logger=error_logger, debug_logger=debug_logger)
        else:
            # Log results to file if DB is not enabled
            log_dns_results_as_json(args_dict["domain"], args_dict["record_type"], server['ipv4'], server['country'], result, dns_logger)

    # Output format: JSON, YAML, or PrettyTable based on user choice and .env settings
    if args_dict["json"]:
        # Output in JSON format
        print(json.dumps(results, indent=4))
    elif args_dict["yaml"]:
        # Output in YAML format
        print(yaml.dump(results))
    else:
        # If neither JSON nor YAML is requested, check if VISUALIZE_OUTPUT is enabled in the .env file
        if os.getenv("VISUALIZE_OUTPUT", "true").lower() == "true":
            print_pretty_table(results, args_dict["expected"])
        else:
            # Log the result or handle output as no visual output is requested
            print("Output suppressed based on VISUALIZE_OUTPUT setting.")


if __name__ == "__main__":
    main()

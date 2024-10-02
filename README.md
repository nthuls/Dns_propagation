# DNS Propagation Checker

## Overview

The DNS Propagation Checker is a tool designed to monitor DNS changes across multiple DNS servers and notify users of any changes via Discord or email. It also supports querying specific DNS servers, logging results, and optionally storing them in a PostgreSQL or MariaDB database. It is built to be flexible and integrates with environment variables to configure options like notifications, database connections, and logging preferences.

## Features

- **DNS Query**: Query multiple DNS servers for DNS record types (e.g., A, CNAME, MX) and log results.
- **Change Detection**: Detect DNS changes using hash comparison and log changes in the database.
- **Notifications**: Notify via Discord and email when DNS changes are detected.
- **Multiple Output Formats**: Supports output in JSON, YAML, or human-readable tables.
- **Custom DNS Server Lists**: Accept custom DNS server lists in YAML or flat file formats.
- **Database Support**: Optionally store DNS query results in PostgreSQL or MariaDB databases.
- **Error Logging**: Detailed logging of errors and DNS query results.
- **Cron/Service Ready**: Ideal for setting up as a scheduled job for continuous monitoring.

## Installation

1. Clone the repository:

    ```bash
    git clone 
    cd dns-propagation-checker
    ```

2. Install the required Python dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Set up your `.env` file to configure your environment variables (see below for more details).

## Environment Variables

The script uses environment variables to configure various options. Create a `.env` file in the project directory:

```env
USE_DB=true
DB_TYPE=postgresql
DB_NAME=dns_results
DB_USER=db_user
DB_PASSWORD=db_password
DB_HOST=localhost
DB_PORT=5432
ENABLE_DISCORD_NOTIFICATIONS=true
DISCORD_WEBHOOK=https://discordapp.com/api/webhooks/YOUR_WEBHOOK_URL
ENABLE_EMAIL_NOTIFICATIONS=true
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_email_password
ALERT_EMAILS=recipient1@example.com,recipient2@example.com
VISUALIZE_OUTPUT=true
```

- `USE_DB`: Set to `true` to use a database for storing results; `false` to disable.
- `DB_TYPE`: `postgresql` or `mariadb`.
- `DISCORD_WEBHOOK`: Comma-separated list of Discord webhook URLs.
- `ENABLE_EMAIL_NOTIFICATIONS`: Set to `true` to enable email notifications.
- `ALERT_EMAILS`: Comma-separated list of email addresses to send alerts to.
- `VISUALIZE_OUTPUT`: Set to `true` to display results in the console.

## Usage

### Command-Line Arguments

```bash
python dns_checker.py [OPTIONS] TYPE DOMAIN
```

#### Required Arguments

- `TYPE`: The type of DNS record to query (e.g., `A`, `MX`, `CNAME`).
- `DOMAIN`: The domain to query (e.g., `example.com`).

#### Optional Arguments

- `--json`: Output in JSON format.
- `--yaml`: Output in YAML format.
- `--show-default`: Show the default DNS server list.
- `--version`: Print version information.
- `--random N`: Select `N` random DNS servers to query.
- `--country COUNTRY`: Filter DNS servers by country (can be used multiple times).
- `--owner OWNER`: Filter DNS servers by owner (can be used multiple times).
- `--expected EXPECTED`: Specify an expected result (e.g., expected IP address).
- `--server SERVER`: Add specific DNS servers to query (can be used multiple times).
- `--custom_list FILE`: Path to a custom YAML file containing DNS servers.
- `--file FILE`: File containing DNS queries (one per line in the format `TYPE DOMAIN`).
- `--dns_list FILE`: Path to a flat text file of DNS servers.

### Example Usage

#### Query a Domain's A Record

```bash
python dns_checker.py A google.com
```

#### Query from a Custom List of DNS Servers

```bash
python dns_checker.py A google.com --dns_list custom_dns_list.txt
```

#### Query Multiple Domains from a File

```bash
python dns_checker.py --file queries.txt
```

#### Show Default DNS Servers

```bash
python dns_checker.py --show-default
```

### Database Support

If `USE_DB=true`, the script will connect to the database specified in the `.env` file and store query results. Tables for `dns_results` and `dns_hashes` will be automatically created if they do not exist.

### Notifications

- **Discord**: If `ENABLE_DISCORD_NOTIFICATIONS=true`, the script will send alerts to the specified Discord webhooks.
- **Email**: If `ENABLE_EMAIL_NOTIFICATIONS=true`, the script will send email alerts to the specified addresses.

## Logging

Logs are stored in `/var/log/domain/` by default. Ensure the script has the necessary permissions to create and write to this directory.

- **dns_results.log**: Logs DNS query results.
- **error.log**: Logs errors and issues encountered during execution.

## Example `.env` Configuration

```env
USE_DB=true
DB_TYPE=postgresql
DB_NAME=dns_results
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
ENABLE_DISCORD_NOTIFICATIONS=true
DISCORD_WEBHOOK=https://discordapp.com/api/webhooks/YOUR_WEBHOOK_URL
ENABLE_EMAIL_NOTIFICATIONS=true
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=youremail@gmail.com
SMTP_PASSWORD=yourpassword
ALERT_EMAILS=admin@example.com,security@example.com
VISUALIZE_OUTPUT=true
```

To set up your script as a service that runs approximately every 4 hours, follow these steps:

### 1. **Create the Systemd Service File**

1. Open a terminal and create the service file:

   ```bash
   sudo nano /etc/systemd/system/Dns_propagation.service
   ```

2. Add the following content to the file, making sure to adjust the paths if necessary:

   ```ini
   [Unit]
   Description=DNS Propagation Checker Service
   After=network.target

   [Service]
   User=User  # Replace with your username if different
   WorkingDirectory=/home/user/Dns_propagation/
   ExecStart=/usr/bin/python3 /home/user/Dns_propagation/dns_resolver.py --file /home/user/Dns_propagation/dns_queries.txt
   Restart=on-failure
   EnvironmentFile=/home/user/Dns_propagation/.env

   [Install]
   WantedBy=multi-user.target
   ```

3. **Save the file** by pressing `CTRL+X`, then `Y`, and `Enter`.

### 2. **Reload Systemd and Start the Service**

To reload systemd and start your service, run the following commands:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnspropagation.service
sudo systemctl start dnspropagation.service
```

### 3. **Create a Systemd Timer to Run Every 4 Hours**

1. Create the timer file:

   ```bash
   sudo nano /etc/systemd/system/dnspropagation.timer
   ```

2. Add the following content:

   ```ini
   [Unit]
   Description=Run DNS Propagation Checker every 4 hours

   [Timer]
   OnBootSec=10min
   OnUnitActiveSec=4h
   Unit=Dns_propagation.service

   [Install]
   WantedBy=timers.target
   ```

3. **Save the file** by pressing `CTRL+X`, then `Y`, and `Enter`.

### 4. **Enable and Start the Timer**

Enable and start the timer with these commands:

```bash
sudo systemctl enable dnspropagation.timer
sudo systemctl start dnspropagation.timer
```

### 5. **Verify the Timer**

To check the status of the timer and make sure it is running every 4 hours:

```bash
sudo systemctl list-timers --all
```

This will list all active timers, and you should see your `dnspropagation.timer` in the list, scheduled to run every 4 hours.

With these steps, your DNS Propagation Checker will automatically run as a service every 4 hours, restarting if it fails.

## Contributing

Feel free to submit issues, pull requests, or suggestions to improve this tool.

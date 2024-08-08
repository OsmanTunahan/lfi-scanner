# LFI Scanner Tool
Web Penetration tool that detects LFI vulnerability. It can search for sensitive files, such as SSH keys and bash history, and identify running processes on the target server.

## Installation

1. **Clone the Repository:**
   ```sh
   git clone https://github.com/OsmanTunahan/lfi-scanner.git
   cd lfi-scanner
   ```

2. **Install Dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

## Usage

```sh
python lfi-scanner.py -u <URL> -w <Wordlist file> -l <LFI Payload> [options]
```

### Arguments

- `-u <URL>`: Target URL with the vulnerable parameter (e.g., `-u http://example.com/index.php?page=`).
- `-w <Wordlist file>`: Path to the wordlist file containing potential file paths (e.g., `-w payloads/unix.txt`).
- `-l <LFI Payload>`: LFI payload to use (e.g., `-l ../../../../../`).

### Options

- `-pid <Set max pid value>`: Maximum PID value to enumerate (default: 1000).
- `-o <Output file>`: File to write the output to (e.g., `-o output.txt`).
- `-t <Threads>`: Number of threads to use (default: 10).
- `-H <Header>`: Custom header to include in requests (e.g., `-H 'Authorization: Bearer token'`).
- `-c <Cookie>`: Cookie value to include in requests (e.g., `-c 'sessionid=abcd1234'`).
- `-a <User-Agent>`: User-Agent string to include in requests (e.g., `-a 'Mozilla/5.0'`).
- `-p <Proxies>`: Proxy to use for requests (e.g., `-p 127.0.0.1:8080`).

### Example

```sh
python lfi_enumeration_tool.py -u http://example.com/index.php?page= -w payloads/unix.txt -l ../../../../../ -o output.txt -t 20 -H 'Authorization: Bearer token' -c 'sessionid=abcd1234' -a 'Mozilla/5.0' -p 127.0.0.1:8080
```
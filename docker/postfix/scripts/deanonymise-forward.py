#!/usr/bin/env python3
import sys
import io
import subprocess
import resolve
import shutil
from dotenv import load_dotenv
from forward_rewriter import ForwardRewriter
from exceptions import RetryException, AbortException

LOG_FILE = "/var/log/mounted-for-postfix/forward.log"
ENV_FILE = "/etc/postfix/script_env"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")
        f.flush()

def process_headers(stdin, sendmail_stdin, original_recipient, real_recipient):
    rewriter = ForwardRewriter(original_recipient,real_recipient)
    while (line := stdin.readline()):
        if not line:
            break

        # End of headers (Add all the ones that were not processed)
        if line.strip() == b"":
            rewriter.add_missing_headers(sendmail_stdin)
            sendmail_stdin.write(b"\n")  # End of headers
            break

        # Modify Existing headers
        # Switch to string representation
        line = line.decode()
        if ":" in line:
            name, value = line.split(":", 1)
            #Peek to get multiline
            while stdin.peek(1)[:1] in (b' ', b'\t'):
                next_line = stdin.readline().decode()
                line = line + next_line
                value = value + next_line.strip()
            line = rewriter.process_header_line(name.strip(),value.strip(),line.strip())
        #Allow handlers to remove existing headers - We also remove emty lines (these mark body start)
        if (not line) or (not line.strip()):
            continue          
        #Make sure their is a newline after the Header Entry    
        if not (line.endswith('\n') or line.endswith('\r\n')):
            line += '\n'
        if line:
            sendmail_stdin.write(line.encode())        

def forward_email(original_recipient, real_recipient):
    sendmail_cmd = ['/usr/sbin/sendmail', '-i', real_recipient]

    with subprocess.Popen(sendmail_cmd, stdin=subprocess.PIPE) as proc:
        try:
            stdin_buffered = io.BufferedReader(sys.stdin.buffer)
            process_headers(stdin_buffered, proc.stdin, original_recipient, real_recipient)
            shutil.copyfileobj(stdin_buffered, proc.stdin)
            proc.stdin.close()
            ret = proc.wait()
            if ret != 0:
                raise AbortException(f"[ERROR] sendmail exited with {ret}", file=sys.stderr)
            log(f"Forwarded E-Mail for: {original_recipient} to: {real_recipient}")
        except Exception as e:
            raise AbortException(f"[ERROR] Exception forwarding mail: {e}", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: deanonymise-forward.py <recipient>", file=sys.stderr)
        sys.exit(1)

    original_recipient = sys.argv[1]
    load_dotenv(ENV_FILE)
    try:
        real_recipient = resolve.deanonymize_recipient(original_recipient)
        forward_email(original_recipient, real_recipient)
    except AbortException as e:
        print(f"[ERROR] Exception forwarding mail: {e}", file=sys.stderr)
        sys.exit(67)
    except RetryException as e:
        print(f"[ERROR] Exception forwarding mail: {e}", file=sys.stderr)
        sys.exit(75)

    sys.exit(0)

if __name__ == "__main__":
    main()
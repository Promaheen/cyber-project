import socket
import time
import sys

def simulate_port_scan(target_ip, num_packets=250):
    print(f"[*] Starting simulated SYN scan against {target_ip}...")
    print(f"[*] Sending {num_packets} rapid connection attempts to trigger Network Agent.")
    
    # We will just try to connect to a random closed port rapidly
    # Since our logic triggers on any TCP packets, this will simulate high traffic
    port = 8080 
    
    count = 0
    start_time = time.time()
    
    try:
        for _ in range(num_packets):
            # Create a new socket for each attempt to generate fresh SYN packets
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01) # Very short timeout so we move fast
            
            try:
                 s.connect((target_ip, port))
            except (socket.timeout, ConnectionRefusedError):
                 pass # We expect it to fail if port is closed, we just want to send the packet
            finally:
                 s.close()
                 
            count += 1
            
            if count % 50 == 0:
                print(f"    Sent {count} connection attempts...")
                
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        
    duration = time.time() - start_time
    print(f"\n[*] Finished sending {count} packets in {duration:.2f} seconds.")
    print("[*] Check your Cybersecurity Dashboard to see if the Network Agent blocked this IP.")

if __name__ == "__main__":
    
    # If a target IP is provided (like a Kali VM), use it.
    # Otherwise, default to triggering the local interface.
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    
    simulate_port_scan(target)

import socket
import threading
import time

BROADCAST_IP = "255.255.255.255"
PORT = 25256
MESSAGE = "Test Broadcast Message"

def send_broadcast():
    """Sends a broadcast message periodically."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        while True:
            sock.sendto(MESSAGE.encode(), (BROADCAST_IP, PORT))
            print(f"Broadcasted: {MESSAGE}")
            time.sleep(5)  # Broadcast every 5 seconds
    except KeyboardInterrupt:
        print("Stopped broadcasting.")
    finally:
        sock.close()

def listen_broadcast():
    """Listens for broadcast messages."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))

    try:
        print(f"Listening for broadcasts on port {PORT}...")
        while True:
            data, addr = sock.recvfrom(1024)  # Receive data (up to 1024 bytes)
            print(f"Received message: {data.decode()} from {addr}")
    except KeyboardInterrupt:
        print("Stopped listening.")
    finally:
        sock.close()

if __name__ == "__main__":
    # Start broadcasting and listening in separate threads
    threading.Thread(target=send_broadcast, daemon=True).start()
    threading.Thread(target=listen_broadcast, daemon=True).start()

    try:
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        print("\nExiting script.")

import socket
import hashlib
import os

# --- CONFIGURATION ---
PORT = 65432
MOVES = ['ROCK', 'PAPER', 'SCISSORS']

# --- CRYPTO & GAME LOGIC ---

def get_valid_move(player_name):
    while True:
        move = input(f"[{player_name}] Enter your move (ROCK/PAPER/SCISSORS): ").strip().upper()
        if move in MOVES:
            return move
        print("Invalid move. Try again.")

def generate_nonce(length=16):
    return os.urandom(length).hex()

def create_commitment(move, nonce):
    """Returns SHA256(move + nonce)"""
    data = (move + nonce).encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def determine_winner(my_move, opponent_move):
    if my_move == opponent_move:
        return "DRAW"
    
    winning_combos = {
        'ROCK': 'SCISSORS',
        'PAPER': 'ROCK',
        'SCISSORS': 'PAPER'
    }
    
    if winning_combos[my_move] == opponent_move:
        return "YOU WIN"
    else:
        return "YOU LOSE"

# --- NETWORK ROLES ---

def run_host():
    """Acts as the Server (Bob)"""
    print(f"\n--- HOSTING GAME ON PORT {PORT} ---")
    print("Waiting for opponent to connect...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow reusing the address to avoid "Address already in use" errors
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', PORT))
        s.listen()
        conn, addr = s.accept()
        
        with conn:
            print(f"Opponent connected from {addr}")
            play_as_bob(conn)

def run_guest():
    """Acts as the Client (Alice)"""
    print("\n--- JOINING GAME ---")
    target_ip = input("Enter Host IP Address: ")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((target_ip, PORT))
            print("Connected successfully!")
            play_as_alice(s)
        except ConnectionRefusedError:
            print("Connection failed. Is the host running?")

# --- PROTOCOL IMPLEMENTATION ---

def play_as_alice(sock):
    """
    ALICE ROLE (The Committer):
    1. Pick Move + Nonce
    2. Send Hash
    3. Receive Bob's Move
    4. Reveal Move + Nonce
    """
    print("\n--- YOU ARE ALICE (The Committer) ---")
    
    # 1. Commit
    move = get_valid_move("Alice")
    nonce = generate_nonce()
    commitment = create_commitment(move, nonce)
    
    print(f"Generated Nonce: {nonce}")
    print(f"Sending Commitment Hash: {commitment}...")
    sock.sendall(commitment.encode())
    
    # 2. Wait for Bob
    print("Waiting for Bob's move...")
    bob_move = sock.recv(1024).decode()
    print(f"Bob played: {bob_move}")
    
    # 3. Reveal
    print("Revealing secret to Bob...")
    reveal_msg = f"{move}:{nonce}"
    sock.sendall(reveal_msg.encode())
    
    # 4. Result (Calculated locally)
    result = determine_winner(move, bob_move)
    print(f"\nResult: {result}")


def play_as_bob(sock):
    """
    BOB ROLE (The Verifier):
    1. Receive Hash
    2. Pick Move & Send it
    3. Receive Alice's Reveal
    4. Verify Hash & Determine Winner
    """
    print("\n--- YOU ARE BOB (The Verifier) ---")
    
    # 1. Receive Commitment
    print("Waiting for Alice's commitment...")
    alice_hash = sock.recv(1024).decode()
    print(f"Received Hash: {alice_hash}")
    
    # 2. Play
    move = get_valid_move("Bob")
    print(f"Sending move '{move}' to Alice...")
    sock.sendall(move.encode())
    
    # 3. Receive Reveal
    print("Waiting for Alice to reveal...")
    data = sock.recv(1024).decode()
    alice_move, alice_nonce = data.split(':')
    
    # 4. Verify
    print(f"Verifying... Alice claims '{alice_move}' with nonce '{alice_nonce}'")
    check_hash = create_commitment(alice_move, alice_nonce)
    
    if check_hash == alice_hash:
        print("SUCCESS: Hash matches. Fair play confirmed.")
        result = determine_winner(move, alice_move)
        print(f"\nResult: {result}")
    else:
        print("ERROR: CHEATING DETECTED! Hashes do not match.")


if __name__ == "__main__":
    print("Rock Paper Scissors - Secure Network Protocol")
    print("1. Host a game")
    print("2. Join a game")
    
    choice = input("Choose (1/2): ")
    
    if choice == '1':
        run_host()
    elif choice == '2':
        run_guest()
    else:
        print("Invalid choice.")
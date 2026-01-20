import numpy as np
import time
from termcolor import colored
from dualRegev import *

def string_to_chunks(text, n):
    ascii_vals = [ord(c) for c in text]
    chunks = []
    for i in range(0, len(ascii_vals), n):
        chunk = ascii_vals[i : i + n]
        while len(chunk) < n: chunk.append(32)          # adding space to final chunks -> len(chunk) = n
        chunks.append(np.array(chunk).reshape(n, 1))
    return chunks

def chunks_to_string(chunks):
    text = ""
    for chunk in chunks:
        flat = chunk.flatten()
        for val in flat:
            if 32 <= val <= 126: text += chr(val)
            else: text += "?"
    return text

def new_key_gen():
    # MEASURE KEY GENERATION
    print(colored("[Timing] Generating Keys...", "grey"))
    t_start = time.perf_counter()
    ask, apk, dk, tk = agen(2**22)
    t_end = time.perf_counter()
    print(colored(f"   -> Key Gen Time: {(t_end - t_start):.4f} seconds", "grey"))
    
    par = apk[0]
    p, q, n, m_bar, alpha, std_dev = par
    print(colored(f"[System] Block size n={n}", "grey"))
    return ask, apk, dk, tk, p, q, n

def run_program(choice, ask, apk, dk, tk, p, q, n):
    
    fake_str = input("\nEnter FAKE message: ")
    real_str = input("Enter REAL message: ")
    
    fake_chunks = string_to_chunks(fake_str, n)
    real_chunks = string_to_chunks(real_str, n)
    max_blocks = max(len(fake_chunks), len(real_chunks))
    
    empty_block = np.full((n, 1), 32, dtype=int)
    while len(fake_chunks) < max_blocks: fake_chunks.append(empty_block)
    while len(real_chunks) < max_blocks: real_chunks.append(empty_block)
    
    ciphertexts = []
    dec_fake = []
    dec_real = []
    if choice == "1":
        # Fully anamorphic encryption
        # MEASURE ENCRYPTION
        t_start = time.perf_counter()
        for i in range(max_blocks):
            c_txt = aenc(apk, dk, fake_chunks[i], real_chunks[i])
            ciphertexts.append(c_txt)
        t_end = time.perf_counter()
        print(colored(f"   -> Encryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        # MEASURE STANDARD DECRYPTION (DICTATOR VIEW)
        t_start = time.perf_counter()
        for i in range(max_blocks):
            m = dec(ask, ciphertexts[i], p, q)
            dec_fake.append(m)
        t_end = time.perf_counter()
        print(colored(f"   -> Standard Decryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        # 4. MEASURE ANAMORPHIC DECRYPTION (RECEIVER)
        t_start = time.perf_counter()
        for i in range(max_blocks):
            m = adec(apk, dk, tk, ask, ciphertexts[i])
            dec_real.append(m)
        t_end = time.perf_counter()
        print(colored(f"   -> Anamorphic Decryption Time: {(t_end - t_start):.4f} seconds", "grey"))
        
        print(colored("\nDictator View: ", "green") + chunks_to_string(dec_fake))
        print(colored("Receiver View: ", "magenta") + chunks_to_string(dec_real[i] for i in range(len(dec_real))))

    elif choice == "2":
        # Anamorphic with normal decryption
        # MEASURE ENCRYPTION
        t_start = time.perf_counter()
        for i in range(max_blocks):
            c_txt = aenc(apk, dk, fake_chunks[i], real_chunks[i])
            ciphertexts.append(c_txt)
        t_end = time.perf_counter()
        print(colored(f"   -> Encryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        # MEASURE STANDARD DECRYPTION (DICTATOR VIEW)
        t_start = time.perf_counter()
        for i in range(max_blocks):
            m = dec(ask, ciphertexts[i], p, q)
            dec_fake.append(m)
        t_end = time.perf_counter()
        print(colored(f"   -> Standard Decryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        print(colored("\nDictator View: ", "green") + chunks_to_string(dec_fake))

    elif choice == "3":
        # Anamorphic with normal encryption
        # MEASURE ENCRYPTION
        t_start = time.perf_counter()
        for i in range(max_blocks):
            c_txt = enc(apk, fake_chunks[i])
            ciphertexts.append(c_txt)
        t_end = time.perf_counter()
        print(colored(f"   -> Encryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        # MEASURE STANDARD DECRYPTION (DICTATOR VIEW)
        t_start = time.perf_counter()
        for i in range(max_blocks):
            m = dec(ask, ciphertexts[i], p, q)
            dec_fake.append(m)
        t_end = time.perf_counter()
        print(colored(f"   -> Standard Decryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        print(colored("\nDictator View: ", "green") + chunks_to_string(dec_fake))

    else:
        # Normal mode
        sk, pk = kgen(q)
        # MEASURE ENCRYPTION
        t_start = time.perf_counter()
        for i in range(max_blocks):
            c_txt = enc(pk, fake_chunks[i])
            ciphertexts.append(c_txt)
        t_end = time.perf_counter()
        print(colored(f"   -> Encryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        # MEASURE STANDARD DECRYPTION (DICTATOR VIEW)
        t_start = time.perf_counter()
        for i in range(max_blocks):
            m = dec(sk, ciphertexts[i], p, q)
            dec_fake.append(m)
        t_end = time.perf_counter()
        print(colored(f"   -> Standard Decryption Time: {(t_end - t_start):.4f} seconds", "grey"))

        print(colored("\nDictator View: ", "green") + chunks_to_string(dec_fake))


def show_menu():
    print("\n=== ANAMORPHIC MESSENGER ===")
    print("1) Mode 1 - Fully anamorphic encryption")
    print("2) Mode 2 - Anamorphic with normal decryption")
    print("3) Mode 3 - Anamorphic with normal encryption")
    print("4) Mode 4 - Normal mode")
    print("0) Exit")

if __name__ == "__main__":
    ask, apk, dk, tk, p, q, n = new_key_gen()
    while True:
            show_menu()
            choice = input("Choose a mode (0-4): ").strip()
            if choice == "0":
                print("Goodbye!")
                break
            # Validate numeric input
            try:
                num = int(choice)
            except ValueError:
                print("Invalid input. Please enter a number between 0 and 4.")
                continue

            run_program(choice, ask, apk, dk, tk, p, q, n)
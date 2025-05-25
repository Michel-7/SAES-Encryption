import sys
import string

S_BOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
]

INV_S_BOX = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
]

RCON = [0x80, 0x30]

def gf_mul(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        high = a & 0x8
        a <<= 1
        if high:
            a ^= 0b10011
        b >>= 1
    return p & 0xF

def sub_nibble(n):
    return S_BOX[n >> 2][n & 0x3]

def inv_sub_nibble(n):
    return INV_S_BOX[n >> 2][n & 0x3]

def sub_word(w):
    return (sub_nibble(w >> 4) << 4) | sub_nibble(w & 0xF)

def rot_word(w):
    return ((w << 4) | (w >> 4)) & 0xFF

def key_expansion(key):
    w = [0] * 6
    w[0] = (key >> 8) & 0xFF
    w[1] = key & 0xFF
    w[2] = w[0] ^ sub_word(rot_word(w[1])) ^ RCON[0]
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ sub_word(rot_word(w[3])) ^ RCON[1]
    w[5] = w[4] ^ w[3]
    return [
        (w[0] << 8) | w[1],
        (w[2] << 8) | w[3],
        (w[4] << 8) | w[5]
    ]

def to_state(block):
    return [
        [(block >> 12) & 0xF, (block >> 4) & 0xF],
        [(block >> 8) & 0xF, block & 0xF]
    ]

def from_state(state):
    return (
        (state[0][0] << 12) | (state[1][0] << 8) |
        (state[0][1] << 4) | state[1][1]
    )

def sub_nibbles_state(state):
    return [[sub_nibble(n) for n in row] for row in state]

def inv_sub_nibbles_state(state):
    return [[inv_sub_nibble(n) for n in row] for row in state]

def shift_rows(state):
    return [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]]
    ]

def inv_shift_rows(state):
    return [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]]
    ]

def mix_columns(state):
    return [
        [
            gf_mul(state[0][0], 1) ^ gf_mul(state[1][0], 4),
            gf_mul(state[0][1], 1) ^ gf_mul(state[1][1], 4)
        ],
        [
            gf_mul(state[0][0], 4) ^ gf_mul(state[1][0], 1),
            gf_mul(state[0][1], 4) ^ gf_mul(state[1][1], 1)
        ]
    ]

def inv_mix_columns(state):
    return [
        [
            gf_mul(state[0][0], 9) ^ gf_mul(state[1][0], 2),
            gf_mul(state[0][1], 9) ^ gf_mul(state[1][1], 2)
        ],
        [
            gf_mul(state[0][0], 2) ^ gf_mul(state[1][0], 9),
            gf_mul(state[0][1], 2) ^ gf_mul(state[1][1], 9)
        ]
    ]

def add_round_key_state(state, key):
    key_state = to_state(key)
    return [
        [state[0][0] ^ key_state[0][0], state[0][1] ^ key_state[0][1]],
        [state[1][0] ^ key_state[1][0], state[1][1] ^ key_state[1][1]]
    ]

def encrypt_block(p, keys):
    state = to_state(p)
    state = add_round_key_state(state, keys[0])

    state = sub_nibbles_state(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key_state(state, keys[1])

    state = sub_nibbles_state(state)
    state = shift_rows(state)
    state = add_round_key_state(state, keys[2])

    return from_state(state)

def decrypt_block(c, keys):
    state = to_state(c)
    state = add_round_key_state(state, keys[2])

    state = inv_shift_rows(state)
    state = inv_sub_nibbles_state(state)
    state = add_round_key_state(state, keys[1])

    state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_nibbles_state(state)
    state = add_round_key_state(state, keys[0])

    return from_state(state)

def ecb_encrypt(hex_text, key):
    keys = key_expansion(key)
    blocks = [int(hex_text[i:i+4], 16) for i in range(0, len(hex_text), 4)]
    return ''.join(f'{encrypt_block(b, keys):04X}' for b in blocks)

def ecb_decrypt(hex_text, key):
    keys = key_expansion(key)
    blocks = [int(hex_text[i:i+4], 16) for i in range(0, len(hex_text), 4)]
    return ''.join(f'{decrypt_block(b, keys):04X}' for b in blocks)

def text_to_hex_blocks(text):
    hexstr = text.encode('utf-8').hex().upper()  # text to hex
    if len(hexstr) % 4 != 0:
        hexstr += '0' * (4 - len(hexstr) % 4)
    return hexstr

def hex_blocks_to_text(hexstr):
    bytes_obj = bytes.fromhex(hexstr) # remove 0 padding added
    try:
        return bytes_obj.decode('utf-8').rstrip('\x00')
    except UnicodeDecodeError:
        return "<Invalid UTF-8 content>"

def ecb_encrypt_text(text, key):
    hexstr = text_to_hex_blocks(text)
    keys = key_expansion(key)
    blocks = [int(hexstr[i:i+4], 16) for i in range(0, len(hexstr), 4)]
    encrypted = [encrypt_block(b, keys) for b in blocks]
    return ''.join(f'{b:04X}' for b in encrypted)

def ecb_decrypt_to_text(cipher_hex, key):
    keys = key_expansion(key)
    blocks = [int(cipher_hex[i:i+4], 16) for i in range(0, len(cipher_hex), 4)]
    decrypted = ''.join(f'{decrypt_block(b, keys):04X}' for b in blocks)
    return hex_blocks_to_text(decrypted)


def is_likely_plaintext(text):
    return all(c in string.printable for c in text) and any(c.isalpha() for c in text)

def brute_force_decrypt(cipher_hex, verbose=False):
    print("🔍 Starting brute-force key search...")
    for key in range(0x0000, 0x10000):
        try:
            pt = ecb_decrypt_to_text(cipher_hex, key)
            if pt == "<Invalid UTF-8 content>":
                continue
            if is_likely_plaintext(pt):
                print(f"\n🎯 Found likely match!")
                print(f"Key: {key:04X}")
                print(f"Plaintext: {pt}")
                return key, pt
            elif verbose:
                print(f"Key {key:04X} → {pt}")
        except:
            continue
    print("❌ No match found.")
    return None, None

# Menu interface
def main():
    while True:
        print("\n--- Simplified AES (S-AES) ---")
        print("1. Encrypt Text")
        print("2. Decrypt Hex")
        print("3. Brute-force Decrypt")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            message = input("Enter message to encrypt: ")
            key = int(input("Enter 4-digit hex key (e.g., 2475): "), 16)
            ciphertext = ecb_encrypt_text(message, key)
            print(f"Encrypted (hex): {ciphertext}")

        elif choice == '2':
            cipher_hex = input("Enter ciphertext (hex, 4*n digits): ").upper()
            key = int(input("Enter 4-digit hex key (e.g., 2475): "), 16)
            plaintext = ecb_decrypt_to_text(cipher_hex, key)
            print(f"Decrypted message: {plaintext}")

        elif choice == '3':
            cipher_hex = input("Enter ciphertext (hex): ").upper()
            verbose = input("Verbose mode? (y/n): ").lower() == 'y'
            brute_force_decrypt(cipher_hex, verbose)

        elif choice == '4':
            sys.exit()
        else:
            print("Invalid option!")

if __name__ == "__main__":
    main()

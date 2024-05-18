
# Given parameters
initial_key = "00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001"
key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
perm_choice01 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
perm_choice02 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# Utility functions (splitting, permutations, rotations)
def split(text):
    half_length = len(text) // 2
    return text[:half_length], text[half_length:]
def permute(text, permutation):
    new_text = ""
    for bit in permutation:
        new_text += text[bit - 1]
    return new_text
def rotate(text, v):
    return text[v:] + text[:v]

# Function for parsing parity bits.
def insert_odd_parity_bit(key_56_bit):
    def odd_parity(bits):
        return '1' if bits.count('1') % 2 == 0 else '0'

    key_64_bit = []
    for i in range(0, 56, 7):
        seven_bits = key_56_bit[i:i+7]
        parity_bit = odd_parity(seven_bits)
        key_64_bit.extend(seven_bits)
        key_64_bit.append(parity_bit)
    return ''.join(key_64_bit)

# Function responsible for generating the keys to be used in the fiestel squares 
def keygen(key, methodType):
    key = key.replace(" ", "")
    keyPlus = permute(key, perm_choice01)                       # Permutes the keys based on PC1, this ignores all the parity bits included in the string
    c1, d1 = split(keyPlus)                                     # Splitting the key into 2 28-bit halves
    keys = [None] * 16
    for k in range(0, 16):
        c1 = rotate(c1, key_shifts[k])
        d1 = rotate(d1, key_shifts[k])
        key = permute((c1+d1), perm_choice02)
        keys[k] = key
    no_Parity_Key = c1+d1
    parity_Key = insert_odd_parity_bit(no_Parity_Key)
    readable_Key = ""
    # Breaking the key into readable 8-bit chunks
    for j in range(0, 64):
        if j % 8 != 0 and j > 0:
            readable_Key += parity_Key[j]
        else: 
            readable_Key += " " + parity_Key[j]
    if methodType == "encrypt":
        return keys
    else:
        if methodType == "decrypt":
            keys.reverse()
            return keys

keys = keygen(initial_key, 'encrypt')
keys2 = keygen(initial_key, 'decrypt')
for i in range(len(keys)):
    print(f"Round {i}, Encryption: {keys[i]}")
    print(f"Round {i}, Decryption: {keys2[i]}")

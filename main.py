'''
Authors: Mathieu Guisard c3256835
         Jaret Posner
        
About This Program:
The purpose of this program is to demonstrate DES encryption and its implementation

'''

# A function to split blocks of text in half, returning the 2 halves as a tuple
def split(text):
    half_length = len(text) // 2
    return text[:half_length], text[half_length:]

# A function which will be called to permute keys based on the permutation order input
def permute(key, permutation):
    new_Key = ""
    for bit in permutation:
        current = bit-1
        new_Key+= key[current]
    return new_Key

# A function which shifts all bits in a key to the left by an increment of v, and the first v bits go to the end of the queue
def rotate(text, v):
    text += text[:v]
    text = text[v:]
    return text

# The Initial Permutation order for the plaintext
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
# The Final Permutation order for the plaintext
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
#The Schedule of Left-Shifts for Key Permutation
shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# Master Key Permutation choices for their first permutations. The master key gets split into 2 keys: C0 and D0
perm_choice01_C0 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
perm_choice01_D0 = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# Permutation Choice 2 extracts 48 bits for a subkey which is used in each step of the encryption process
perm_choice02 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

def main():
    # The plaintext message "This is simply a test text to verify the code is working", converted to binary
    plaintext = "01010100 01101000 01101001 01110011 00100000 01101001 01110011 00100000 01110011 01101001 01101101 01110000 01101100 01111001 00100000 01100001 00100000 01110100 01100101 01110011 01110100 00100000 01110100 01100101 01111000 01110100 00100000 01110100 01101111 00100000 01110110 01100101 01110010 01101001 01100110 01111001 00100000 01110100 01101000 01100101 00100000 01100011 01101111 01100100 01100101 00100000 01101001 01110011 00100000 01110111 01101111 01110010 01101011 01101001 01101110 011001111"
    plaintext = plaintext.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(plaintext) % 8 != 0:
        plaintext += "0"*(8-len(plaintext) % 8)

    # The initial encryption Key
    original_Key = "00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001"
    original_Key = original_Key.replace(" ", "")

    # Split the plaintext into left and right halves
    plaintext_left, plaintext_right = split(plaintext)
    ciphertext1 = permute(plaintext, IP)
    l0, r0 = split(ciphertext1)


    c0 = permute(original_Key, perm_choice01_C0)
    d0 = permute(original_Key, perm_choice01_D0)

    c1 = rotate(c0, 1)
    d1 = rotate(d0, 1)

    k1 = permute((c1+d1), perm_choice02)
    print(k1)
    print(len(k1))

if __name__ == "__main__":
    main()
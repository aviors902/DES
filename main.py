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
    return text[v:] + text[:v]

# A quick method of returning the sbox desired value. The sbox argument is where the relevant 2d array sbox will be passed through, the coordinate is a 6 bit binary number which will be converted into 2d coordinates within the array
def sbox(sbox_array, coordinate):
    # Ensure sbox_inputs has at least 48 characters by padding with zeros
    sbox_inputs = coordinate.zfill(48)
    row = int(sbox_inputs[0] + sbox_inputs[5], 2)  # Convert binary row coordinate to integer
    column = int(sbox_inputs[1:5], 2)  # Convert binary column coordinate to integer
    return format(sbox_array[row][column], '04b')  # Return result as 4-bit binary string


# A binary xor function, converting the binary strings to integers, performing the xor operation and then returning the result
def binary_xor(bin_str1, bin_str2):
    # Convert binary strings to integers
    int_val1 = int(bin_str1, 2)
    int_val2 = int(bin_str2, 2)
    # Perform bitwise XOR operation
    result = int_val1 ^ int_val2
    # Convert result back to binary string
    result_bin_str = bin(result)[2:]  # Remove '0b' prefix
    # Pad with zeros to ensure the length matches the longer input string
    max_len = max(len(bin_str1), len(bin_str2))
    result_bin_str = result_bin_str.zfill(max_len)
    # Convert result back to binary string
    result_bin_str = format(result, 'b')
    return result_bin_str

# The Initial Permutation order for the plaintext
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
# The Final Permutation order for the plaintext
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
#The Schedule of Left-Shifts for Key Permutation
key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# Master Key Permutation choices for their first permutations. The master key gets split into 2 keys: C0 and D0
perm_choice01_C0 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
perm_choice01_D0 = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# Permutation Choice 2 extracts 48 bits for a subkey which is used in each step of the encryption process
perm_choice02 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
# The expansion permutation for increasing Rn from 32 bits to 48
expansion = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# The S-Boxes are written as 2d Arrays
sbox_1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

sbox_2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
]

sbox_3 = [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
]

sbox_4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
]

sbox_5 = [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
]

sbox_6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
]

sbox_7 = [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
]

sbox_8 = [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
]


def main():
    # The plaintext message "This is simply a test text to verify the code is working", converted to binary
    plaintext = "01010100 01101000 01101001 01110011 00100000 01101001 01110011 00100000 01110011 01101001 01101101 01110000 01101100 01111001 00100000 01100001 00100000 01110100 01100101 01110011 01110100 00100000 01110100 01100101 01111000 01110100 00100000 01110100 01101111 00100000 01110110 01100101 01110010 01101001 01100110 01111001 00100000 01110100 01101000 01100101 00100000 01100011 01101111 01100100 01100101 00100000 01101001 01110011 00100000 01110111 01101111 01110010 01101011 01101001 01101110 011001111"
    plaintext = plaintext.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(plaintext) % 8 != 0:
        plaintext += "0"*(8-len(plaintext) % 8)

    # Split the plaintext into left and right halves
    ciphertext = permute(plaintext, IP)
    old_Left, old_Right = split(ciphertext)

     # The initial encryption Key
    original_Key = "00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001"
    original_Key = original_Key.replace(" ", "")
    c1 = permute(original_Key, perm_choice01_C0)
    d1 = permute(original_Key, perm_choice01_D0)

    for n in range(1, 17):
        print(n)

        c1 = rotate(c1, key_shifts[n-1])
        d1 = rotate(d1, key_shifts[n-1])
        operation_key = permute((c1+d1), perm_choice02)

        # Permuting based on the function of (L(n-1) XOR (Sbox Output of R(n-1) XOR Kn))
        sbox_inputs = binary_xor(old_Right, operation_key)
        sbox_inputs = sbox_inputs.zfill(48)  # Ensure sbox_inputs is exactly 48 bits long
        print("sbox inputs: ", sbox_inputs, " - size: ", len(sbox_inputs))

        sbox_output_1 = sbox(sbox_1, sbox_inputs[:6])
        sbox_output_2 = sbox(sbox_2, sbox_inputs[6:12])
        sbox_output_3 = sbox(sbox_3, sbox_inputs[12:18])
        sbox_output_4 = sbox(sbox_4, sbox_inputs[18:24])
        sbox_output_5 = sbox(sbox_5, sbox_inputs[24:30])
        sbox_output_6 = sbox(sbox_6, sbox_inputs[30:36])
        sbox_output_7 = sbox(sbox_7, sbox_inputs[36:42])
        sbox_output_8 = sbox(sbox_8, sbox_inputs[42:])

        sbox_output = sbox_output_1 + sbox_output_2 + sbox_output_3 + sbox_output_4 + sbox_output_5 + sbox_output_6 + sbox_output_7 + sbox_output_8
        print("sbox output: ", sbox_output, " Size: ", len(sbox_output))
        new_Right = binary_xor(old_Left, sbox_output)

        # Resetting variables for the loop to iterate again.
        old_Left = old_Right
        old_Right = new_Right





if __name__ == "__main__":
    main()

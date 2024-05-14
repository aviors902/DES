'''
Authors: Mathieu Guisard c3256835
         Jaret Posner
        
About This Program:
The purpose of this program is to demonstrate DES encryption and its implementation

'''
# The Initial Permutation order for the plaintext
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
# Inverse Initial Permutation is used for the decryption process. It takes the encrypted message and arranges the bits into the same order they were placed during the very first encryption step
IP_Inverse = inverse_IP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,9, 49, 17, 57, 25]
# The Final Permutation order for the plaintext
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
# Permutation P is the permutation made at the end of each fiestel round
permutation_p = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
# The Schedule of Left-Shifts for Key Permutation
key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# Master Key Permutation choices for their first permutations. The master key gets split into 2 keys: C0 and D0
perm_choice01_C0 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
perm_choice01_D0 = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# Permutation Choice 2 extracts 48 bits for a subkey which is used in each step of the encryption process
perm_choice02 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
# Permutation choice inverse01 is the inverse initial permutation of the encryption keys, used for decryption
perm_choice_inverse01 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# Permutation choice 2 inverse is the inverse of permutation choice 2 used in the encryption algorythm
perm_choice_inverse02 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
# The expansion permutation for increasing Rn from 32 bits to 48
expansion = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

def sbox_Permutation(sbox_input):
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
    sbox_output_1 = sbox(sbox_1, sbox_input[:6])
    sbox_output_2 = sbox(sbox_2, sbox_input[6:12])
    sbox_output_3 = sbox(sbox_3, sbox_input[12:18])
    sbox_output_4 = sbox(sbox_4, sbox_input[18:24])
    sbox_output_5 = sbox(sbox_5, sbox_input[24:30])
    sbox_output_6 = sbox(sbox_6, sbox_input[30:36])
    sbox_output_7 = sbox(sbox_7, sbox_input[36:42])
    sbox_output_8 = sbox(sbox_8, sbox_input[42:])
    sbox_output = sbox_output_1 + sbox_output_2 + sbox_output_3 + sbox_output_4 + sbox_output_5 + sbox_output_6 + sbox_output_7 + sbox_output_8


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


# A function which shifts all bits in a key to the direction specified by an increment of v
def rotate(text, v, direction):
    if direction == 'l':
        return text[v:] + text[:v]
    else:
        if direction == 'r':
            return text[-v:] + text[:-v]


# A quick method of returning the sbox desired value. The sbox argument is where the relevant 2d array sbox will be passed through, the coordinate is a 6 bit binary number which will be converted into 2d coordinates within the array
def sbox(sbox_array, coordinate):
    row = int(coordinate[0] + coordinate[5], 2)                                         # Convert binary row coordinate to integer
    column = int(coordinate[1:5], 2)                                                    # Convert binary column coordinate to integer
    return format(sbox_array[row][column], '04b')                                       # Return result as 4-bit binary string - '04b' indicating a 4-bit ('04') binary ('b') number


# A binary xor function, converting the binary strings to integers, performing the xor operation and then returning the result
def binary_xor(bin_str1, bin_str2):
    # Convert strings to binary
    bin_val1 = int(bin_str1, 2)
    bin_val2 = int(bin_str2, 2)
    result = bin_val1 ^ bin_val2                                                        # Perform bitwise XOR operation
    result_bin_str = format(result, 'b')                                                # Convert result back to binary string
    max_len = max(len(bin_str1), len(bin_str2))
    result_bin_str = result_bin_str.zfill(max_len)                                      # Pad the output with zeros to ensure the length matches the longer input string    
    return result_bin_str


def encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(plaintext) % 8 != 0:
        plaintext += "0"*(8-len(plaintext) % 8)

    # Split the plaintext into left and right halves
    ciphertext = permute(plaintext, IP)
    old_Left, old_Right = split(ciphertext)
    key = key.replace(" ", "")
    c1 = permute(key, perm_choice01_C0)
    d1 = permute(key, perm_choice01_D0)

    # This for loop is the 17 Fiestel rounds taken in DES encryption
    for n in range(1, 17):
        #print(n)                                                                        Debugging Print statement - Just used to indicate which iteration is being performed

        # Generating the new encryption key (Rotate c1 and d1 to the left by 1, join them and then permute)
        new_Left = old_Right
        c1 = rotate(c1, key_shifts[n-1], 'l')
        d1 = rotate(d1, key_shifts[n-1], 'l')
        operation_key = permute((c1+d1), perm_choice02)
        #print("key: ", operation_key, " - size: ", len(operation_key))                 # Debugging print statement
        #Expanding the old right from 32-bits to 48-bits to XOR it with the encryption key
        old_Right = permute(old_Right, expansion)
        # Permuting based on the function of (L(n-1) XOR (Sbox Output of R(n-1) XOR Kn))
        sbox_input = binary_xor(old_Right, operation_key)
        #sbox_input = sbox_input.zfill(48)                                              # Ensure sbox_inputs is exactly 48 bits long
        #print("sbox inputs: ", sbox_input, " - size: ", len(sbox_input))               # Debugging print statement
        sbox_output = sbox_Permutation(sbox_input)
        # p is the final permutation of the right hand side before XORing it with the old Left hand side
        p = permute(sbox_output, permutation_p)
        # The new_Right (Rn) is formulated by performing an XOR operation on the old left (Ln-1) and the permuted s-box function output
        new_Right = binary_xor(old_Left, p)
        # Update all variables for the next iteration of the loop
        old_Left = new_Left
        old_Right = new_Right


    # After 16 rounds of permutations, the final permutation FP is performed
    final_permutation = permute(new_Right + new_Left, FP)
    readable_ciphertext = ""
    # A small loop just breaking the binary string into 8-bit sections
    for i in range(len(final_permutation)):
        if i % 8 != 0 and i > 0:
            readable_ciphertext += final_permutation[i]
        else: 
            readable_ciphertext += " " + final_permutation[i]

    return readable_ciphertext, operation_key                                           # Returning a tuple of 2 objects: The Binary String containing the encrypted message, followed by the final encryption key used (So the text can be decrypted)


def decrypt(ciphertext, decryption_key):  
    ciphertext = ciphertext.replace(" ", "")                                            # Removing white space from the ciphertext and padding it to ensure it is exactly a multople of 8 bits long
    if len(ciphertext) % 8 != 0:
        ciphertext += "0"*(8-len(ciphertext) % 8)
    ciphertext = permute(ciphertext, FP)
    new_Left, new_Right = split(ciphertext)
    old_Left, old_Right = split(ciphertext)
    operation_Key = permute(decryption_key, perm_choice_inverse02)

    for d in range(1, 17):

        new_Right = permute(old_Right, permutation_p)
        new_Right = permute(new_Right, expansion)
        sbox_output = sbox_Permutation(new_Right)

        new_Right = binary_xor(sbox_output, old_Left)
        old_Right = new_Right
        old_Left = new_Left

        c0, d0 = split(operation_Key)
        c0 = rotate(c0, key_shifts[d-1], 'r')
        d0 = rotate(d0, key_shifts[d-1], 'r')
        operation_Key = permute(c0+d0, perm_choice_inverse02)    


    plaintext = permute(new_Left+new_Right, IP_Inverse)
    
    
    plaintext = ''
    original_Key = permute(c0+d0, perm_choice_inverse01)
    return plaintext, original_Key



def main():
    # The plaintext message "0123456789ABCDEF", converted from hex to binary
    plaintext = "00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111"

    # The initial encryption Key K = 133457799BBCDFF1 in Hex, converted to Binary
    key = "00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001"

    message, decryption_key = encrypt(plaintext, key)


    print(message)
    print("Decryption Key: ", decryption_key)


if __name__ == "__main__":
    main()
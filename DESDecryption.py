'''
Authors: Mathieu Guisard c3256835
         Jaret Posner c3355817
        
About This Program:
The purpose of this program is to demonstrate DES encryption and its implementation

'''

import os.path # Used for file io
import webbrowser # Used for opening file in the browser
import datetime # Used so that new files don't overwrite old files, and are seperated by date.

# The Initial Permutation order for the plaintext
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
# The Final Permutation order for the plaintext - The inverse of the Initial Permutation
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
# Permutation P is the permutation made at the end of each fiestel round
permutation_p = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
# The Schedule of Left-Shifts for Key Permutation
key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# Master Key Permutation choices for their first permutations. The master key gets split into 2 keys: C0 and D0
perm_choice01 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# Permutation Choice 2 extracts 48 bits for a subkey which is used in each step of the encryption process
perm_choice02 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
# Permutation choice inverse01 is the inverse initial permutation of the encryption keys, used for decryption
perm_choice_inverse01 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
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
    return sbox_output_1 + sbox_output_2 + sbox_output_3 + sbox_output_4 + sbox_output_5 + sbox_output_6 + sbox_output_7 + sbox_output_8


# A function to split blocks of text in half, returning the 2 halves as a tuple
def split(text):
    half_length = len(text) // 2
    return text[:half_length], text[half_length:]


# A function which will be called to permute text based on the permutation order input
def permute(text, permutation):
    new_Text = ""
    for bit in permutation:
        new_Text += text[bit-1]
    return new_Text


# A function which shifts all bits in a key to the direction specified by an increment of v
def rotate(text, v):
    return text[v:] + text[:v]


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


# Takes a given 56-bit key and returns it as a 64-bit key with each 8th-bit as an odd-parity-bit 
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
    keyPlus = permute(key, perm_choice01)                                               # Permutes the keys based on PC1, this ignores all the parity bits included in the string
    c1, d1 = split(keyPlus)                                                             # Splitting the key into 2 28-bit halves
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
        

# Used to compare the number of bits that differ between 2 binary string inputs (Assumes that the strings are the exact same length)
def compareBitDifferences(input, permutation):
    count = 0
    for bit in range(len(permutation)):
        if permutation[bit-1] != input[bit-1]:
            count += 1
    return count

# - Read/Write Files -

# Used to ask the get the file from disk
def readFilePrompt():
    print("Enter the path of the file you want to read from: ")
    # Read user input
    requestedFile = input("")
    if (os.path.isfile(requestedFile) == False):
        print("File path is not valid")
        quit()
    # Test if it is txt
    if (requestedFile.endswith('.txt') == False):
        print("File must be a .txt file format")
        quit()
    # Then return the path if it is valid
    return requestedFile

def readFile(path):
    # Open the file
    with open(path, 'r') as file:
        data = file.read()
    # Remove the starting parts.
    data = data.replace('p:','')
    data = data.replace('p2:','')
    data = data.replace('k:','')
    data = data.replace('k2:','')
    # Remove the prefixes for the c parts
    data = data.replace('c00:','') # DES 0, ciphertext 1
    data = data.replace('c01:','') # DES 0, ciphertext 2
    data = data.replace('c02:','') # DES 0, ciphertext 3
    data = data.replace('c03:','') # DES 0, ciphertext 4
    data = data.replace('c10:','') # DES 1, ciphertext 1
    data = data.replace('c11:','') # DES 1, ciphertext 2
    data = data.replace('c12:','') # DES 1, ciphertext 3
    data = data.replace('c13:','') # DES 1, ciphertext 4
    data = data.replace('c20:','') # DES 2, ciphertext 1
    data = data.replace('c21:','') # DES 2, ciphertext 2
    data = data.replace('c22:','') # DES 2, ciphertext 3
    data = data.replace('c23:','') # DES 2, ciphertext 4
    data = data.replace('c30:','') # DES 3, ciphertext 1
    data = data.replace('c31:','') # DES 3, ciphertext 2
    data = data.replace('c32:','') # DES 3, ciphertext 3
    data = data.replace('c33:','') # DES 3, ciphertext 4
    # Pack everything into an array, so its easier to work with.
    data_as_array = data.splitlines()
    # Return the value
    return data_as_array

def writeFile(data, decryptedArray):
    time = datetime.datetime.now()
    fileName = f"Decryption_output_{time.year}-{time.month}-{time.day}-{time.hour}-{time.minute}-{time.second}"
    print(f"Writing to file \"{fileName}\"")
    # Write to file
    outputFile = open(fileName,"w")
    outputFile.write(f"""Avalanche Demonstration
          
Plaintext p  = {data[0]}
Plaintext p' = {data[1]}
        
Key k:  {data[2]}
Key k': {data[3]}

Ciphertexts generated using plaintext p under key k
DES0 = {data[4]}
DES1 = {data[5]}
DES2 = {data[6]}
DES3 = {data[7]}

Ciphertexts generated using plaintext p' under key k
DES0 = {data[8]}
DES1 = {data[9]}
DES2 = {data[10]}
DES3 = {data[11]}
        
Ciphertexts generated using plaintext p under key k'
DES0 = {data[12]}
DES1 = {data[13]}
DES2 = {data[14]}
DES3 = {data[15]}

Ciphertexts generated using plaintext p' under key k'
DES0 = {data[16]}
DES1 = {data[17]}
DES2 = {data[18]}
DES3 = {data[19]}

-------------------------------------

Decrypting p under k
Using DES0 - Plaintext p:{decryptedArray[0]})
Using DES1 - Plaintext p:{decryptedArray[1]})
Using DES2 - Plaintext p:{decryptedArray[2]})
Using DES3 - Plaintext p:{decryptedArray[3]})

Decrypting p' under k
Using DES0 - Plaintext p':{decryptedArray[4]}
Using DES1 - Plaintext p':{decryptedArray[5]}
Using DES2 - Plaintext p':{decryptedArray[6]}
Using DES3 - Plaintext p':{decryptedArray[7]}

Decrypting p under k'
Using DES0 - Plaintext p:{decryptedArray[8]}
Using DES1 - Plaintext p:{decryptedArray[9]}
Using DES2 - Plaintext p:{decryptedArray[10]}
Using DES3 - Plaintext p:{decryptedArray[11]}

Decrypting p' under k'
Using DES0 - Plaintext p':{decryptedArray[12]}
Using DES1 - Plaintext p':{decryptedArray[13]}
Using DES2 - Plaintext p':{decryptedArray[14]}
Using DES3 - Plaintext p':{decryptedArray[15]}
""")
    outputFile.close()
    # Tell user where file was outputted
    print(f"File was outputted to \"{fileName}\"")
    # Open it
    webbrowser.open(fileName)

# - DES Implementations -

# The Full function DES0 is the complete DES encryption and decryption process with no steps omitted or modified.
# Returns the encrypted (or decrypted) message and an array containing the number of bits that differ from the input message at each stage in the fiestel squares
def DES0(message, key, encryptOrDecrypt):
    message = message.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(message) % 8 != 0:
        message += "0"*(8-len(message) % 8)

    bitDifferences = []

    # Split the plaintext into left and right halves
    ciphertext = permute(message, IP)
    old_Left, old_Right = split(ciphertext)
    bitDifferences.append(compareBitDifferences(ciphertext, message))
    keys = keygen(key, encryptOrDecrypt)
    # This for loop is the 17 Fiestel rounds taken in DES encryption
    for operation_key in keys:
        # Generating the new encryption key (Rotate c1 and d1 to the left by 1, join them and then permute)
        new_Left = old_Right
        #Expanding the old right from 32-bits to 48-bits to XOR it with the encryption key
        old_Right = permute(old_Right, expansion)
        # Permuting based on the function of (L(n-1) XOR (Sbox Output of R(n-1) XOR Kn))
        sbox_input = binary_xor(old_Right, operation_key)
        #print("sbox inputs: ", sbox_input, " - size: ", len(sbox_input))               # Debugging print statement
        sbox_output = sbox_Permutation(sbox_input)
        # p is the final permutation of the right hand side before XORing it with the old Left hand side
        p = permute(sbox_output, permutation_p)
        # The new_Right (Rn) is formulated by performing an XOR operation on the old left (Ln-1) and the permuted s-box function output
        new_Right = binary_xor(old_Left, p)
        # Update all variables for the next iteration of the loop
        old_Left = new_Left
        old_Right = new_Right
        bitDifferences.append(compareBitDifferences(old_Left+old_Right, message))       # Counting the number of bits that differ from the original message
    # After 16 rounds of permutations, the final permutation FP is performed - Right and Left are swapped one final time
    final_permutation = permute(new_Right + new_Left, FP)
    readable_ciphertext = ""
    # A small loop just breaking the binary string into 8-bit sections for easier reading
    for i in range(len(final_permutation)):
        if i % 8 != 0 and i > 0:
            readable_ciphertext += final_permutation[i]
        else: 
            readable_ciphertext += " " + final_permutation[i]
    return readable_ciphertext, bitDifferences                                           # Returning a tuple of 2 objects: The Binary String containing the encrypted message, followed by an array indicating the number of bits that differ between the original message and the permutation of that message at that point in the fiestel loop


# Implementing DES1 - DES encryption with a step removed - XOR with round key removed
# Returns the encrypted (or decrypted) message and an array containing the number of bits that differ from the input message at each stage in the fiestel squares
def DES1(message, key, encryptOrDecrypt):
    message = message.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(message) % 8 != 0:
        message += "0"*(8-len(message) % 8)

    # Split the plaintext into left and right halves
    ciphertext = permute(message, IP)
    old_Left, old_Right = split(ciphertext)
    bitDifferences = []
    bitDifferences.append(compareBitDifferences(ciphertext, message))

    # This for loop is the 16 Fiestel rounds taken in DES encryption
    for k in range(0, 16):
        # Generating the new encryption key (Rotate c1 and d1 to the left by 1, join them and then permute)
        new_Left = old_Right
        # Expanding the old right from 32-bits to 48-bits to XOR it with the encryption key
        old_Right = permute(old_Right, expansion)
        # In DES0, the sbox_Input would be old_Right XOR Round Key. DES1 is to show the difference in the encryption without the XOR
        sbox_input = old_Right
        sbox_output = sbox_Permutation(sbox_input)
        # p is the final permutation of the right hand side before XORing it with the old Left hand side
        p = permute(sbox_output, permutation_p)
        # The new_Right (Rn) is formulated by performing an XOR operation on the old left (Ln-1) and the permuted s-box function output
        new_Right = binary_xor(old_Left, p)
        # Update all variables for the next iteration of the loop
        old_Left = new_Left
        old_Right = new_Right
        bitDifferences.append(compareBitDifferences(old_Left+old_Right, message))       # Counting the number of bits that differ from the original message
    # After 16 rounds of permutations, the final permutation FP is performed - Right and Left are swapped one final time
    final_permutation = permute(new_Right + new_Left, FP)
    readable_ciphertext = ""
    # A small loop just breaking the binary string into 8-bit sections for easier reading
    for i in range(len(final_permutation)):
        if i % 8 != 0 and i > 0:
            readable_ciphertext += final_permutation[i]
        else: 
            readable_ciphertext += " " + final_permutation[i]
    return readable_ciphertext, bitDifferences                                           # Returning a tuple of 2 objects: The Binary String containing the encrypted message, followed by an array indicating the number of bits that differ between the original message and the permutation of that message at that point in the fiestel loop


# Implementing DES2 - SBOX permutations have been removed and replaced with the inverse of the expansion box
# Returns the encrypted (or decrypted) message and an array containing the number of bits that differ from the input message at each stage in the fiestel squares
def DES2(message, key, encryptOrDecrypt):
    inverse_Expansion = [2, 3, 4, 5, 8, 9, 10, 11, 14, 15, 16, 17, 20, 21, 22, 23, 26, 27, 28, 29, 32, 33, 34, 35, 38, 39, 40, 41, 44, 45, 46, 47]
    message = message.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(message) % 8 != 0:
        message += "0"*(8-len(message) % 8)
    bitDifferences = []
    # Split the plaintext into left and right halves
    ciphertext = permute(message, IP)
    old_Left, old_Right = split(ciphertext)
    bitDifferences.append(compareBitDifferences(ciphertext, message))
    keys = keygen(key, encryptOrDecrypt)
    # This for loop is the 16 Fiestel rounds taken in DES encryption
    for operation_key in keys:
        # Generating the new encryption key (Rotate c1 and d1 to the left by 1, join them and then permute)
        new_Left = old_Right
        #Expanding the old right from 32-bits to 48-bits to XOR it with the encryption key
        old_Right = permute(old_Right, expansion)
        # Permuting based on the function of (L(n-1) XOR (Sbox Output of R(n-1) XOR Kn))
        sbox_input = binary_xor(old_Right, operation_key)
        shrunk = permute(sbox_input, inverse_Expansion)
        # p is the final permutation of the right hand side before XORing it with the old Left hand side
        p = permute(shrunk, permutation_p)
        # The new_Right (Rn) is formulated by performing an XOR operation on the old left (Ln-1) and the permuted s-box function output
        new_Right = binary_xor(old_Left, p)
        # Update all variables for the next iteration of the loop
        old_Left = new_Left
        old_Right = new_Right
        bitDifferences.append(compareBitDifferences(old_Left+old_Right, message))       # Counting the number of bits that differ from the original message
    # After 16 rounds of permutations, the final permutation FP is performed - Right and Left are swapped one final time
    final_permutation = permute(new_Right + new_Left, FP)
    readable_ciphertext = ""
    # A small loop just breaking the binary string into 8-bit sections for easier reading
    for i in range(len(final_permutation)):
        if i % 8 != 0 and i > 0:
            readable_ciphertext += final_permutation[i]
        else: 
            readable_ciphertext += " " + final_permutation[i]
    return readable_ciphertext, bitDifferences                                           # Returning a tuple of 2 objects: The Binary String containing the encrypted message, followed by an array indicating the number of bits that differ between the original message and the permutation of that message at that point in the fiestel loop


# Implementing DES3 - No Permutation P at the end of each Fiestel Box
# Returns the encrypted (or decrypted) message and an array containing the number of bits that differ from the input message at each stage in the fiestel squares
def DES3(message, key, encryptOrDecrypt):
    message = message.replace(" ", "")
    #Padding the text to ensure it remains an exact multiple of 64 bits (8 bytes)
    if len(message) % 8 != 0:
        message += "0"*(8-len(message) % 8)
    bitDifferences = []
    # Split the plaintext into left and right halves
    ciphertext = permute(message, IP)
    old_Left, old_Right = split(ciphertext)
    bitDifferences.append(compareBitDifferences(ciphertext, message))
    keys = keygen(key, encryptOrDecrypt)
    # This for loop is the 16 Fiestel rounds taken in DES encryption
    for operation_key in keys:
        # Generating the new encryption key (Rotate c1 and d1 to the left by 1, join them and then permute)
        new_Left = old_Right
        #Expanding the old right from 32-bits to 48-bits to XOR it with the encryption key
        old_Right = permute(old_Right, expansion)
        # Permuting based on the function of (L(n-1) XOR (Sbox Output of R(n-1) XOR Kn))
        sbox_input = binary_xor(old_Right, operation_key)
        #print("sbox inputs: ", sbox_input, " - size: ", len(sbox_input))               # Debugging print statement
        sbox_output = sbox_Permutation(sbox_input)
        # The new_Right (Rn) is formulated by performing an XOR operation on the old left (Ln-1) and the permuted s-box function output
        new_Right = binary_xor(old_Left, sbox_output)
        # Update all variables for the next iteration of the loop
        old_Left = new_Left
        old_Right = new_Right
        bitDifferences.append(compareBitDifferences(old_Left+old_Right, message))       # Counting the number of bits that differ from the original message
    # After 16 rounds of permutations, the final permutation FP is performed - Right and Left are swapped one final time
    final_permutation = permute(new_Right + new_Left, FP)
    readable_ciphertext = ""
    # A small loop just breaking the binary string into 8-bit sections for easier reading
    for i in range(len(final_permutation)):
        if i % 8 != 0 and i > 0:
            readable_ciphertext += final_permutation[i]
        else: 
            readable_ciphertext += " " + final_permutation[i]
    return readable_ciphertext, bitDifferences                                           # Returning a tuple of 2 objects: The Binary String containing the encrypted message, followed by an array indicating the number of bits that differ between the original message and the permutation of that message at that point in the fiestel loop


def main():
    # - File Reading -

    inputFile = readFilePrompt() # Get the input file...
    data = readFile(inputFile) #... then assign it to the message.

    k = data[2] # K value is on line 3, which is 2 in the array.
    k2 = data[3] # K' value is on line 4. 3 in array.
    
    # - DES Methods -

    decryptedArray = [0] * 16 # Place to store the decrypted plaintext to pass it to the output

    # Implementing DES0 - The Standard DES encryption process with zero changes decrypting c00 with key k
    decryptedArray[0], decryptBitDifference00 = DES0(data[4], k, 'decrypt')
    # Implementing DES1 - DES encryption with a step removed - XOR with round key removed decrypting c01 with key k
    decryptedArray[1], decryptBitDifference01 = DES1(data[5], k, 'decrypt')
    # Implementing DES2 - SBOX permutations have been removed and replaced with the inverse of the expansion box decrypting c02 with key k
    decryptedArray[2], decryptBitDifference02 = DES2(data[6], k, 'decrypt')
    # Implementing DES3 - No Permutation P at the end of each Fiestel Box decrypting c03 with key k
    decryptedArray[3], decryptBitDifference03 = DES3(data[7], k, 'decrypt')

    # Implementing DES0 - The Standard DES encryption process with zero changes decrypting c10 with key k
    decryptedArray[4], decryptBitDifference10 = DES0(data[8], k, 'decrypt') 
    # Implementing DES1 - DES encryption with a step removed - XOR with round key removed decrypting c11 with key k
    decryptedArray[5], decryptBitDifference11 = DES1(data[9], k, 'decrypt')
    # Implementing DES2 - SBOX permutations have been removed and replaced with the inverse of the expansion box decrypting c12 with key k
    decryptedArray[6], decryptBitDifference12 = DES2(data[10], k, 'decrypt')
    # Implementing DES3 - No Permutation P at the end of each Fiestel Box decrypting c13 with key k
    decryptedArray[7], decryptBitDifference13 = DES3(data[11], k, 'decrypt')

    # Implementing DES0 - The Standard DES encryption process with zero changes decrypting c20 with key k'
    decryptedArray[8], decryptBitDifference20 = DES0(data[12], k2, 'decrypt')
    # Implementing DES1 - DES encryption with a step removed - XOR with round key removed c21 with key k'
    decryptedArray[9], decryptBitDifference21 = DES1(data[13], k2, 'decrypt')
    # Implementing DES2 - SBOX permutations have been removed and replaced with the inverse of the expansion box c22 with key k'
    decryptedArray[10], decryptBitDifference22 = DES2(data[14], k2, 'decrypt')
    # Implementing DES3 - No Permutation P at the end of each Fiestel Box c23 with key k'
    decryptedArray[11], decryptBitDifference23 = DES3(data[15], k2, 'decrypt')

    # Implementing DES0 - The Standard DES encryption process with zero changes c30 with key k'
    decryptedArray[12], decryptBitDifference30 = DES0(data[16], k2, 'decrypt')
    # Implementing DES1 - DES encryption with a step removed - XOR with round key removed c31 with key k'
    decryptedArray[13], decryptBitDifference31 = DES1(data[17], k2, 'decrypt')
    # Implementing DES2 - SBOX permutations have been removed and replaced with the inverse of the expansion box c32 with key k'
    decryptedArray[14], decryptBitDifference32 = DES2(data[18], k2, 'decrypt')
    # Implementing DES3 - No Permutation P at the end of each Fiestel Box c33 with key k'
    decryptedArray[15], decryptBitDifference33 = DES3(data[19], k2, 'decrypt')

    #TODO: Write to file
    writeFile(data,decryptedArray)
    
if __name__ == "__main__":
    main()

# Code references
# [1] [https://stackoverflow.com/questions/82831/how-do-i-check-whether-a-file-exists-without-exceptions] <22 May 24>
# [2] [https://stackoverflow.com/questions/70797/user-input-and-command-line-arguments} <22 May 24>
# [3] [https://www.w3schools.com/python/python_user_input.asp] <22 May 24>
# [4] [https://stackoverflow.com/questions/73663/how-do-i-terminate-a-script] <22 May 24>
# [5] [https://stackoverflow.com/a/8369345] <22 May 24>
# [6] [https://stackoverflow.com/questions/37372603/how-to-remove-specific-substrings-from-a-set-of-strings-in-python] <22 May 24>
# [7] [https://stackoverflow.com/questions/22042948/split-string-using-a-newline-delimiter-with-python] <22 May 24>
# [8] [https://www.askpython.com/python/array/initialize-a-python-array] <22 May 24>
# [9] [https://www.w3schools.com/python/python_file_write.asp] <22 May 24>
# [10] [https://stackoverflow.com/questions/6178154/open-a-text-file-using-notepad-as-a-help-file-in-python] <22 May 24>
# [11] [https://sentry.io/answers/write-one-or-more-lines-to-a-file-in-python/] <22 May 24>
# [12] [https://www.w3docs.com/snippets/python/how-can-i-print-variable-and-string-on-same-line-in-python.html] <22 May 24>

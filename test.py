import os.path # Used for file io
import webbrowser # Used for opening file in the browser
import datetime # Used so that new files don't overwrite old files, and are seperated by date.

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
    # Open the specified file Path
    with open(path, 'r') as file:
        data = file.read()
    data_as_array = data.splitlines()
    # Returns the array - index 0 is p, index 1 is p', index 2 is k and index 3 is k'
    return data_as_array


def writeFile(output):
    time = datetime.datetime.now()
    fileName = f"Encryption_output_{time.year}-{time.month}-{time.day}-{time.hour}-{time.minute}-{time.second}"
    print(f"Writing to file \"{fileName}\"")
    # Write to file
    outputFile = open(fileName,"w")
    outputFile.write(output)
    return

import os

# Print the current working directory
print(f"Current working directory: {os.getcwd()}")

# Check if the file exists and its size
file_path = "DECRYPTION_SAMPLE_INPUT.txt"
if os.path.exists(file_path):
    print(f"The file '{file_path}' exists.")
    file_size = os.path.getsize(file_path)
    print(f"The file size is {file_size} bytes.")
    if file_size == 0:
        print("The file is empty.")
else:
    print(f"The file '{file_path}' does not exist.")

# Open the file and read the contents into an array
try:
    with open(file_path, "r") as file:
        raw_content = file.read()
        print(f"Raw content of the file:\n{raw_content}")  # Print the raw content of the file
        array = raw_content.splitlines()  # Split the raw content into lines
except FileNotFoundError:
    print("The file DECRYPTION_SAMPLE_INPUT.txt was not found.")
    array = []

# Debugging: Print the contents of the array
print(f"Contents of the array after processing: {array}")

# Check if array is not empty before accessing elements
if array:
    try:
        output = array[0]
        print(f"First element of the array: {output}")
    except IndexError as e:
        print(f"Error accessing element of array: {e}")
else:
    print("The array is empty.")

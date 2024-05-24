# DES Encryption - COMP3260 A2

This is the README for the DES implementation created for COMP3260's second assignment, as implmented by Mathieu Guisard & Jaret Posner

## Execution

Run the python scripts from the command line using "./PROGRAM-NAME.py"
Both DESEncryption and DESDecryption will ask you for a filepaath. Use absolute filepaths
The input file should be .txt format, laid out in the same way as the sample text files.
View "Encryption_Sample.txt" & "Decryption_Sample.txt" for layout examples for input files

Decryption needs line 1 and 2 are 64-bit plaintext blocks (In binary)
Line 3 and 4 are 64-bit encryption keys to be used in the processes (Also in binary)

Results of the programs will be put into an output file, and the input filepath will be the output file location File name will conside of Encryption or Decryption process, followed by the date and time the program was run

DESEncryption displays the encryption process and DESDecryption displays the decryption process.

## References

Wikipedia contributors, “Data Encryption Standard,” Wikipedia, Apr. 14, 2024. https://en.wikipedia.org/wiki/Data_Encryption_Standard (Accessed May. 10, 2024)
Wikipedia contributors, “DES supplementary material,” Wikipedia, Nov. 06, 2023. https://en.wikipedia.org/wiki/DES_supplementary_material (accessed May 10, 2024).
“The DES algorithm illustrated,” page.math.tu. No Publication Date Given. https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm (accessed May 10, 2024).

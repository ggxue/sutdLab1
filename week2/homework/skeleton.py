#!/usr/bin/env python
# Skeleton for Security Tools Lab 1 - Simple ciphers
# Student ID: 1007399
# StudentName: Xue Haige

import binascii as b
import requests
import json
import argparse
import socket # IPs/Ports validation:
import nltk # question 5
import collections # question 6
import binascii # question 6

def log_p_text_string(index, string, name):
    with open(f'{name} output.txt', 'a', encoding='utf-8') as f:
        log_entry = f"Index: {index}, String: {string}\n"
        f.write(log_entry)

# question 5:
# ----------------------------------------------------------------------------------------------------------------------------------------
def resolvePlainChallenge():
    """
        Solution of plain challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type': 'application/json'}

    r = requests.get(url + 'challenges/plain')
    data = r.json()
    print("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    a = data['challenge'][2:]
    s = bytearray.fromhex(a).decode()

    payload = {'cookie': data['cookie'], 'solution': s}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url + 'solutions/plain', headers=headers, data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

def is_valid_english_sentence(sentence):
        # tokenize the sentence into words
        words = nltk.word_tokenize(sentence)

        # check if all words are valid English words
        for word in words:
            if not nltk.corpus.words.words().__contains__(word.lower()):
                return False

        return True
    
def caesarChallengeSolution(c_hex_arr):
    p_text_string = ""

    # convert each ciphered hex into ciphered decimal
    decimal_array = list(map(lambda x: int(str(x), 16), c_hex_arr))

    ascii_length = 255
    for i in range(1, ascii_length):
        for num in decimal_array:
            p_text_string += chr((num-i) % ascii_length)
            # print("check:")
            # print(p_text_string)
        log_p_text_string(i, p_text_string, 'caesar')
        if is_valid_english_sentence(p_text_string):
            # print("valid")
            # print(p_text_string)
            break
        else:
            # print("invalid")
            p_text_string = ""

    return p_text_string

def resolveCaesarChallenge():
    """
        Solution of caesar challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/caesar')
    data = r.json()
    print("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    s=data['challenge'][2:]
    s=b.unhexlify(s)
    solution = caesarChallengeSolution(s)
    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/caesar', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)
    
# question 5 plain text answer:
# erroneous. when i said that you stimulated me i meant, to be frank, that in noting your fallacies i was occasionally guided towards the truth. not that you are entirely wrong in this instance. the man is certainly a country practitioner. and he walks a good deal." "then i was right." "to that extent." "but that was all."
# "no, no, my dear watson, not all--by no means all. i would suggest, for example, that a presentation to a doctor is more likely to come from a hospital than from a hunt, and that whe the initials 'c.c.' are placed before that hospital the word 'charing cross' very naturally suggest themselves. "you may be right. "the probability lies in that direction. and if we take this as  working hypothesis we have a fresh basis from which to start ou construction of this unknown visitor." "well, then, supposing that 'c.c.h.' does stand for 'charing cross hospital,' what further inference.
# ----------------------------------------------------------------------------------------------------------------------------------------
    
    
# question 6:
# ----------------------------------------------------------------------------------------------------------------------------------------
# function to calculate the frequency distribution of letters in a given text
def calculate_frequencies(text):
    counter = collections.Counter(text)
    total = len(text)
    frequencies = {letter: (count / total) * 100 for letter, count in counter.items()}
    return frequencies

def substitutionChallengeSolution(s):
    # define the frequency distribution of letters in the English language
    english_frequencies = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02,
        'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11,
        'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11,
        'j': 0.10, 'z': 0.07
    }

    # convert hex string to ASCII
    byte_string = binascii.unhexlify(s)
    try:
        ascii_text = byte_string.decode('utf-8')
    except UnicodeDecodeError:
        # fallback to Latin-1 encoding
        ascii_text = byte_string.decode('latin-1')

    # calculate letter frequencies in the ciphered text
    ciphered_frequencies = calculate_frequencies(ascii_text.lower())

    # sort the ciphered frequencies dictionary by values in descending order
    sorted_ciphered_frequencies = {
        k: v for k, v in sorted(ciphered_frequencies.items(), key=lambda item: item[1], reverse=True)
    }

    # match the most frequent letters in the ciphered text with the corresponding English letter frequencies
    mapping = {}
    for ciphered_letter in sorted_ciphered_frequencies.items():
        english_letter = max(english_frequencies, key=lambda x: english_frequencies[x])
        mapping[ciphered_letter] = english_letter

    # decrypt the ciphered text using the mapping
    p_text_string = ''.join(mapping.get(letter, letter) for letter in ascii_text)

    # print the deciphered text
    log_p_text_string(1, p_text_string, 'substitution')
    return p_text_string
    
def resolvesubstitutionChallenge():
    """
        Solution of substitution challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/substitution')
    data = r.json()
    #print ("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    s=data['challenge'][2:]
    s = substitutionChallengeSolution(s)
    solution = s

    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/substitution', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)
# ----------------------------------------------------------------------------------------------------------------------------------------


# question 7:
# ----------------------------------------------------------------------------------------------------------------------------------------
def xor_strings(plaintext, hex_string):
        # convert hex string to bytes
        bytes_hex = bytes.fromhex(hex_string)
        # convert plaintext to bytes
        bytes_plain = plaintext.encode()
        # Perform XOR operation
        result = bytearray(a ^ b for a, b in zip(bytes_plain, bytes_hex))
        # convert result back to binary string
        xor_result = ''.join(format(byte, '08b') for byte in result)
        return xor_result
    
def binary_to_hex(binary):
    decimal_value = int(binary, 2)
    hex_value = hex(decimal_value)[2:]  # remove the '0x' prefix
    return hex_value

def resolveotpChallengeSolution(default_c):
    # 1. calculate key using default plain text and server response cipher text
    default_p = "Student ID 1000000 gets 0 points"
    otp = xor_strings(default_p, default_c)

    # 2. get updated cipher text by otp XOR updated plain text
    updated_p = "Student ID 1007399 gets 6 points"
    updated_c = xor_strings(updated_p, binary_to_hex(otp))

    return binary_to_hex(updated_c)
    
def resolveotpChallenge():
    """
        Solution of otp challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/otp')
    data = r.json()
    # print ("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    a = data['challenge'][2:]
    # c = b.unhexlify(a)
    c = resolveotpChallengeSolution(a)
    solution = c

    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/otp', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

# question 7 response:
# [DEBUG] Submitted solution is:
# {
#     "cookie": "0x50ca6ff426d4d686d3af8d8314e95e9d",
#     "solution": "161d0c56130b17493e214562580056465c506b52140116457f42115d2c0b071b"
# }
# [DEBUG] Obtained response: Plaintext of your solution is:
# "Student ID (1007399) gets (6) points"
# ----------------------------------------------------------------------------------------------------------------------------------------


# main function:
# ----------------------------------------------------------------------------------------------------------------------------------------
def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(port):
    return 0 <= int(port) <= 65535

# mandatory parameters --port and --ip:
def parseArgs():
    """ 
        Function for arguments parsing
    """
    aparser = argparse.ArgumentParser(description='Script demonstrates breaking of simple ciphers: Caesar, Substitution cipher, and OTP.', formatter_class = argparse.RawTextHelpFormatter) 
    aparser.add_argument('--port', required=True, metavar='PORT', help='Port of challenge/response server.')
    aparser.add_argument('--ip', required=True, metavar='PORT', help='Port of challenge/response server.')
    aparser.add_argument("--mode", required=True, choices = ['p', 'c', 's', 'o'], help="p => demonstrates hexadecimal encoding challenge.\
                         \nc => demonstrates breaking of the Caesar cipher.\
                         \ns => demonstrates breaking of the Substitution cipher.\
                         \no => demonstrates breaking of the OTP cipher.")
    args = aparser.parse_args()
    
    return args

def main():
    args = parseArgs()

    global IP
    IP = args.ip

    global PORT
    PORT = args.port
    
    print("check IP:")
    print(IP)
    print("check PORT:")
    print(PORT)
    
    # IPs/Ports validation:
    #----------------------------------
    if IP and not validate_ip(IP):
        print("Invalid IP address")
        return
    if PORT and not validate_port(PORT):
        print("Invalid port number")
        return
    #-----------------------------------

    if args.mode == "o":
        resolveotpChallenge()
    elif args.mode == "p":
        resolvePlainChallenge()
    elif args.mode == "c":
        resolveCaesarChallenge()
    elif args.mode == "s":
        resolvesubstitutionChallenge()

if __name__ == '__main__':
    main()
# ----------------------------------------------------------------------------------------------------------------------------------------
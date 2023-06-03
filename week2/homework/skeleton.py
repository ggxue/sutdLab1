#!/usr/bin/env python
# Skeleton for Security Tools Lab 1 - Simple ciphers
# Student ID:
# StudentName:

import binascii as b
import requests
import json
import hashlib
import argparse
import nltk # question 5
import collections # question 6
import binascii # question 6

def xorString(s1,s2):
    """ 
        XOR two strings with each other, return result as string
    """
    rval = [ord(a) ^ ord(b) for a,b in zip(s1,s2)]
    return ''.join([chr(r) for r in rval])


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

# solution functions:
def log_p_text_string(index, string, name):
    with open(f'{name} output.txt', 'a', encoding='utf-8') as f:
        log_entry = f"Index: {index}, String: {string}\n"
        f.write(log_entry)
        
# question 5:
def caesarChallengeSolution(c_hex_arr):
    p_text_string = ""

    # step 2: convert each ciphered hex into ciphered decimal
    decimal_array = list(map(lambda x: int(str(x), 16), c_hex_arr))
    print(decimal_array)

    def is_valid_english_sentence(sentence):
        # Tokenize the sentence into words
        words = nltk.word_tokenize(sentence)

        # Check if all words are valid English words
        for word in words:
            if not nltk.corpus.words.words().__contains__(word.lower()):
                return False

        return True

    ascii_length = 255
    for i in range(1, ascii_length):
        print(i)
        for num in decimal_array:
            p_text_string += chr((num-i) % ascii_length)
            print("check:")
            print(p_text_string)
        log_p_text_string(i, p_text_string, 'caesar')
        if is_valid_english_sentence(p_text_string):
            print("valid")
            print(p_text_string)
            break
        else:
            print("invalid")
            p_text_string = ""

    return p_text_string
#
# question 5 plain text answer:
# erroneous. when i said that you stimulated me i meant, to be frank, that in noting your fallacies i was occasionally guided towards the truth. not that you are entirely wrong in this instance. the man is certainly a country practitioner. and he walks a good deal." "then i was right." "to that extent." "but that was all."
# "no, no, my dear watson, not all--by no means all. i would suggest, for example, that a presentation to a doctor is more likely to come from a hospital than from a hunt, and that whe the initials 'c.c.' are placed before that hospital the word 'charing cross' very naturally suggest themselves. "you may be right. "the probability lies in that direction. and if we take this as  working hypothesis we have a fresh basis from which to start ou construction of this unknown visitor." "well, then, supposing that 'c.c.h.' does stand for 'charing cross hospital,' what further inference.

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
    
# question 6:
def substitutionChallengeSolution(s):
    # Define the frequency distribution of letters in the English language
    english_frequencies = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02,
        'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11,
        'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11,
        'j': 0.10, 'z': 0.07
    }

    # Function to calculate the frequency distribution of letters in a given text
    def calculate_frequencies(text):
        counter = collections.Counter(text)
        total = len(text)
        frequencies = {letter: (count / total) * 100 for letter, count in counter.items()}
        return frequencies

    # Hex string to be deciphered

    # Convert hex string to ASCII
    byte_string = binascii.unhexlify(s)
    try:
        ascii_text = byte_string.decode('utf-8')
    except UnicodeDecodeError:
        # Fallback to Latin-1 encoding
        ascii_text = byte_string.decode('latin-1')

    # Calculate letter frequencies in the ciphered text
    ciphered_frequencies = calculate_frequencies(ascii_text.lower())

    # Sort the ciphered frequencies dictionary by values in descending order
    sorted_ciphered_frequencies = {
        k: v for k, v in sorted(ciphered_frequencies.items(), key=lambda item: item[1], reverse=True)
    }

    # Match the most frequent letters in the ciphered text with the corresponding English letter frequencies
    mapping = {}
    for ciphered_letter in sorted_ciphered_frequencies.items():
        english_letter = max(english_frequencies, key=lambda x: english_frequencies[x])
        mapping[ciphered_letter] = english_letter

    # Decrypt the ciphered text using the mapping
    p_text_string = ''.join(mapping.get(letter, letter) for letter in ascii_text)

    # Print the deciphered text
    print(p_text_string)
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
    s=b.unhexlify(s)
    solution = s

    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/substitution', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

# question 7: wip

def resolveotpChallenge():
    """
        Solution of otp challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/otp')
    data = r.json()
    #print ("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    a = data['challenge'][2:]
    c = b.unhexlify(a)
    solution = c

    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/otp', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

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
    
# --port <port> --ip <ip> --mode = [’p’, ’c’, ’s’, ’o’]).

# trial run -p

# Caesar’s cipher -c

# Frequency Analysis of Substitution Cipher -s

# OTP messages Integrity -o
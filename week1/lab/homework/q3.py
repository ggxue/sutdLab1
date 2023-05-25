
import logging
import hashlib


print('Start')

words = []
words = open('./words5.txt').read().splitlines()
print(words[:10])

hashes = []
hashes = open('./1007399-hash15.txt').read().splitlines()
print(hashes[:10])

output = {}

for h in hashes:
    for w in words:
        if h == hashlib.md5(w.encode()).hexdigest():
            print("found")
            print(h)
            print(w)
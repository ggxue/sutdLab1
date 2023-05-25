import hashlib
hashed = hashlib.md5("password".encode()).hexdigest()
print(hashed)
print(len(hashed))

hashed_2 = hashlib.md5("a super long password".encode()).hexdigest()
print(hashed_2)
print(len(hashed_2))

hashed_3 = hashlib.md5("another even more longer password".encode()).hexdigest()
print(hashed_3)
print(len(hashed_3))

# python md5_lab1.py -i words5.txt -w words.txt -o output.txt
# rtgen md5 loweralpha 1 5 0 3800 600000 0




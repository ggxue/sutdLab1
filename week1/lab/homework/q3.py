import hashlib
import time
import argparse

start_time = time.time()

parser = argparse.ArgumentParser(description='Script description')
parser.add_argument('-i', '--input', type=str, help='Path to the input file', required=True)
parser.add_argument('-w', '--word', type=str, help='Path to the word file', required=True)
parser.add_argument('-o', '--output', type=str, help='Path to the output file', required=True)

args = parser.parse_args()
inputs = open(args.input).read().splitlines()
words = open(args.word).read().splitlines()
output = open(args.output, 'w')

cracked_count = 0
for h in inputs:
    for w in words:
        if h == hashlib.md5(w.encode()).hexdigest():
            output.write('{} : {}\n'.format(w, h))
            cracked_count += 1
            
end_time = time.time()
            
output.write('Dictionary attack completed! Cracked {} out of {}, time taken {}s\n'.format(cracked_count, len(inputs), end_time - start_time))
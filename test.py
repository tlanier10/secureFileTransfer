import json

data = 7

outfile = open('blech.json', 'w+')
json.dump(data, outfile, indent=4)
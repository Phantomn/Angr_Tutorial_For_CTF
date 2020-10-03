import sys
string = "VXRRJEUR"
data = ""

def complex_function(a1, a2):
	return (31 * a2 + a1 - 65) % 26 + 65

def main():
	global string, data
	tmp = ""
	for i in range(0, len(string)):
		for j in range(0x40, 0x5a):
			tmp = chr(complex_function(j, i+8))
			if tmp == string[i]:
				data += chr(j)
				break
	print data

if __name__ == '__main__':
	main()
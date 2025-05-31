# Basic Conditional Statement
a = 1
if a == 1:
    print("Yes")
else:
    print("No")

# ---------------------------------

# Working with Variables and Strings
text = 'Lorem Ipsum'
num1 = 10
num2 = 10.2
isChoice = True

print(f"The value of variable num1 is {num1}")
print(f"The value of variable num2 is {num2}")
print(f"The value of variable isChoice is {isChoice}")
# print("The value of variable num1 is " + str(num1))
# print("The value of variable num2 is " + str(num2))
# print("The value of variable isChoice is " + str(isChoice))

# ---------------------------------

# Input and Type Checking
name = input("Enter your name: ")
print("Name: " + name)

number = float(input("Enter your number: "))
print(type(number))  # Shows data type
print(number)

# Combined Example
name = input("Enter Full name: ")
number = float(input("Enter Number: "))

print("Name: " + name)
print("Number: " + str(number))
print(type(number))

# ---------------------------------

# String Escape Characters
print("Mike said \"I love eating burger!\"")
print('Mike said \'I love eating burger!\'')
print('Mike said "I love eating burger!"')

print("This next text will move to the \nnext line")
print("This next text will move to the \tnext line")

# ---------------------------------

# Multiline String
text = '''
    The quick brown fox
    jumps over the moon
    Hello world
'''
print(text)

# ---------------------------------

# String Formatting
name = "Jeric"
food = "Burger"
game = "FPS"

# Using index-based formatting
sampleText = "My name is {2} i love {1} and playing {0}"
print(sampleText.format(name, food, game))

# Using keyword-based formatting
sampleText = "My name is {newname} i love {newfood} and playing {newgame}"
print(sampleText.format(newname="Mike", newfood="burger", newgame="volleyball"))

# Using % formatting
item = "milk"
cost = 35.50
print("The product %s costs %.2f" % (item, cost))

# Using f-strings
cost = 35.73
item = "milk"
print(f"The product {item} costs {cost * 83:.2f} pesos")

# ---------------------------------

# String Methods
word1 = "HELLO"
word2 = "hi"
word3 = "lorem Ipsum Dolor Amet si"

print(word1.lower())          # Converts to lowercase
print(word2.upper())          # Converts to uppercase
print(word3.capitalize())     # Capitalizes the first letter
print(word3.title())          # Capitalizes each word
print(word3.split(","))       # Splits string by a delimiter
print(word3.replace("Ipsum", "good"))  # Replaces a word
print(len(word3))             # Gets the length of the string

# ---------------------------------

# String Formatting with Variables
item = "milk"
cost = 35.50

# Using % formatting
print("The product %s costs %f" % (item, cost))
print("The product %s costs %.2f" % (item, cost))

# Using f-strings
print(f"The product {item} costs {cost * 83:.2f} pesos")

# Conditional Statements

# Example 1: Check if input number matches a predefined number
number = 10
inpNum = int(input("Enter the number: "))

if inpNum == number:
    print(f"Entered number {inpNum} is equal to the number {number}.")
    print("Good bye!")

# ---------------------------------

# Example 2: Checking a yes/no input for breakfast
isChoice = input("Did you eat your breakfast? (yes/no): ")

if isChoice.lower() == "yes":
    print("Congrats! You already ate breakfast!")
else:
    print("Eat breakfast before coming to class!")

# ---------------------------------

# Example 3: Checking the case of a sentence
sentence1 = "I love eating Pringles"
sentence2 = "I LOVE EATING PRINGLES"

# Logical Operators
# 'or': Skips checking other conditions if the first is True
# 'and': All conditions must be True

sentence = "!WEEEE"  # Example of an uppercase sentence
# sentence = "weee"  # Example of a lowercase sentence

if sentence.isupper():
    print("Please calm down!")
else:
    print("Do not shout!")

# ---------------------------------

# Example 4: Check if a string is numeric
number = "3.14"  # Example of a non-digit numeric value

if number.isdigit():
    print("It is a number")
else:
    print("It is not a number")

# ---------------------------------

# String Methods Summary:
# - isdigit(): Returns True if the string contains digits only
# - isalpha(): Returns True if the string contains alphabets only
# - isalnum(): Returns True if the string contains alphabets or digits only

#------------------------------------------------------------------------------

# Working with Strings and Indexing

sentence = "Hello World"

# Accessing characters using positive and negative indices
print(sentence[6])    # Positive index
print(sentence[-5])   # Negative index

# Positive and negative index example
print("Positive:", sentence[10])
print("Negative:", sentence[-9])

# Slicing strings
print(sentence[3:7])    # From index 3 to 6
print(sentence[3:8])    # From index 3 to 7
print(sentence[-8:-3])  # From index -8 to -4

# More slicing examples
print(sentence[-8:8])    # From index -8 to 7
print(sentence[0:-6])    # From index 0 to -6
print(sentence[-10:4])   # From index -10 to 3

# Notes:
# Negative indices: Left to right (-1 -> size of string itself)
# Positive indices: Right to left (0 -> n-1)

#------------------------------------------------------------------------------

# Working with Lists and Iteration

names = ["steve", "tony", "bruce", 23]
print(type(names))  # Use type() to check data type

# Iterating through a list
for name in names:
    print(name)

# Notes:
# - Heterogeneous (hetero): List can hold multiple data types
# - Homogeneous (homo): List with a single type of data

#------------------------------------------------------------------------------

# Using `range` in Loops

n = 4
for i in range(0, n):
    print(i)  # Outputs: 0 to n-1

# Examples of `range`
for num in range(10):          # 0 -> 9
    print(num)

for num in range(5, 10):       # 5 -> 9
    print(num)

for num in range(-10, 0):      # -10 -> -1
    print(num)

for num in range(5, 11, 5):    # 5, 10 (step = 5)
    print(num)

for num in range(-1, -11, -1): # -1 -> -10 (negative step)
    print(num)

for num in range(10, 0, -1):   # 10 -> 1 (decrement by 1)
    print(num)

# Notes:
# - `range` stops at the value before the `stop` parameter (exclusive).
# - The third argument (step) changes the increment or decrement.
# - Common patterns:
#   * 1 argument: `range(stop)` - starts at 0, increments by 1
#   * 2 arguments: `range(start, stop)` - starts at `start`, increments by 1
#   * 3 arguments: `range(start, stop, step)` - allows control of step, can be positive or negative


#------------------------------------------------------------------------------

# While Loop with Break
i = 1
while i <= 5:
    print("Just me")
    i += 1
    if i == 3:
        break
else:
    print("Loop ended")
print("Outside of the loop")

#------------------------------------------------------------------------------

# While Loop with Continue
i = 1
while i <= 5:
    print("Just me")
    i += 1
    if i == 3:
        continue
else:
    print("Loop ended")
print("Outside of the loop")

#------------------------------------------------------------------------------

# While Loop with User Input
choice = "Y"
while (choice == "Y") or (choice == "y"):
    number = int(input("Enter a number: "))
    choice = input("Do you want to enter again? (Y/N): ")
else:
    print("Good bye!")

# Another Variation of User Input in While Loop
choice = True
while choice:
    number = int(input("Enter a number: "))
    choice_input = input("Do you want to continue? (Y/N): ")
    if choice_input.lower() != "y":
        choice = False
else:
    print("Good bye!")

#------------------------------------------------------------------------------

# Using `pass` in Loops and Conditionals
if 1 < 0:
    pass
else:
    print("This will not be printed")

while True:
    pass  # Infinite loop with no operation


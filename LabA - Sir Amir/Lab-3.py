#------------------------------------------------------------------------------

# # Working with Lists
# thisList = [1.2, 100, "Python", True]
# print(thisList)
# print(type(thisList))
# print(thisList[2])   # Accessing an element
# print(thisList[-4])  # Negative indexing

# #------------------------------------------------------------------------------

# # Check if an Item is in a List
# names = ["Steve", "Tony", "Bruce", "Thor", "Bruce"]
# for name in names:
#     if name == "Bruce":
#         print("Bruce is in the list")
#         break
# else:
#     print("Bruce is not in the list")

# if "Steve" in names:
#     print("Existing")
# else:
#     print("Not existing")

# #------------------------------------------------------------------------------

# # Modifying a List
# names = ["Steve", "Tony", "Bruce", "Thor", "Steve"]
# print(f"Before: {names}")
# names[1] = "Stephen"
# print(f"After: {names}")

# # Insert an Item at a Specific Position
# hero = input("Enter the name to insert: ")
# print(f"Before: {names}")
# names.insert(2, hero)
# print(f"After: {names}")

# # Append an Item to the End
# inp = input("Enter the name to append: ")
# print(f"Before: {names}")
# names.append(inp)
# print(f"After: {names}")

# #------------------------------------------------------------------------------

# # Populating a List with Input in a While Loop
# i = 1
# myList = []
# while i <= 5:
#     temp = input(f"Enter character {i}: ")
#     myList.append(temp)
#     i += 1
# print(myList)

# # Using For Loop to Populate a List
# myList = []
# for num in range(1, 6):
#     temp = input(f"Enter the {num}th character: ")
#     myList.append(temp)
# print(myList)

# #------------------------------------------------------------------------------

# # Removing Items from a List
# avengers = ["Steve", "Tony", "Bruce", "Thor", "Wanda"]

# # Remove by Value
# print(f"Before: {avengers}")
# avengers.remove("Tony")
# print(f"After: {avengers}")

# # Remove by Index or Clear
# print(f"Before: {avengers}")
# avengers.pop(2)       # Removes at index 2
# avengers.pop()        # Removes the last element
# avengers.clear()      # Clears the list
# # del avengers         # Deletes the list
# print(f"After: {avengers}")

# #------------------------------------------------------------------------------

# # Sorting and Reversing a List
# avengers = ["Steve", "Tony", "Bruce", "Thor", "Wanda"]

# avengers.sort()                  # Sorts in ascending order
# avengers.sort(reverse=True)      # Sorts in descending order
# avengers.reverse()               # Reverses the list order


#------------------------------------------------------------------------------

# Lists: []
#     - Ordered: Maintains the order of elements as added
#     - Mutable: Elements can be modified after creation
#     - Allows Duplicates: Can contain multiple identical values

# example_list = [1, 2, 2, "hello", True]
# print(example_list)  # Output: [1, 2, 2, 'hello', True]

# #------------------------------------------------------------------------------

# # Tuples: " " or ()
# #     - Ordered: Maintains the order of elements
# #     - Immutable: Cannot be modified after creation
# #     - Allows Duplicates: Can contain multiple identical values

# example_tuple = (1, 2, 2, "hello", True)
# print(example_tuple)  # Output: (1, 2, 2, 'hello', True)

# # Notes:
# # - Tuples are useful for data that should not change, like coordinates or constant settings.
# # - A single-element tuple needs a trailing comma, e.g., `single_tuple = (1,)`.

# #------------------------------------------------------------------------------

# # Sets: {}
# #     - Unordered: Does not maintain order
# #     - Mutable: You can add or remove elements (but the set itself is immutable in terms of structure)
# #     - Does NOT Allow Duplicates: Eliminates duplicates automatically

# example_set = {1, 2, 2, "hello", True}
# print(example_set)  # Output: {1, 2, 'hello'}

# # Notes:
# # - Sets are great for operations like union, intersection, and difference.
# # - Adding duplicate elements has no effect.

# #------------------------------------------------------------------------------

# # Dictionary: {key: value}
# #     - Ordered: Maintains insertion order (Python 3.7+)
# #     - Mutable (for values): Values can be updated
# #     - Immutable (for keys): Keys cannot be changed once set
# #     - Does NOT Allow Duplicate Keys: Only the most recent key-value pair is retained
# #     - Allows Duplicate Values: Same value can appear multiple times

# example_dict = {
#     "name": "Steve",
#     "age": 30,
#     "skills": ["Python", "JavaScript"],
#     "age": 35  # Overwrites the earlier "age" key
# }
# print(example_dict)
# # Output: {'name': 'Steve', 'age': 35, 'skills': ['Python', 'JavaScript']}

# # Notes:
# # - Keys must be unique and immutable (e.g., strings, numbers, or tuples).
# # - Values can be of any data type, including lists or other dictionaries.
# # - Common operations include accessing, updating, deleting, and iterating.

# # Example of duplicate value:
# duplicate_value_dict = {
#     "key1": "value",
#     "key2": "value"  # Duplicate values are allowed
# }
# print(duplicate_value_dict)  # Output: {'key1': 'value', 'key2': 'value'}

#------------------------------------------------------------------------------

# Tuples: Basics
myTup = ("Apple", "Cherry", "Banana", "Apple")
myTup2 = "a", "b", "c", "d"  # Parentheses are optional for simple tuples

print(myTup)          # Output: ('Apple', 'Cherry', 'Banana', 'Apple')
print(myTup2)         # Output: ('a', 'b', 'c', 'd')
print(myTup[1])       # Output: 'Cherry'

# Tuples are immutable; this line will throw an error:
# myTup[1] = "Strawberry"

print(type(myTup2))   # Output: <class 'tuple'>

#------------------------------------------------------------------------------

# Adding Elements Using Typecasting
myTuple = ()
print(myTuple)        # Output: ()

myList = list(myTuple)  # Convert tuple to list
name = input("Enter your name: ")
myList.append(name)    # Add element to the list
myTuple = tuple(myList)  # Convert back to tuple
print(myTuple)

# Another Way to Add (Concatenation)
myTuple += ("Hiro",)   # Note the comma for single-element tuples
print(myTuple)

#------------------------------------------------------------------------------

# Slicing Tuples
print(myTup[1])        # Output: 'Cherry'
print(myTup[1:3])      # Output: ('Cherry', 'Banana')

#------------------------------------------------------------------------------

# Removing Elements Using Typecasting
myTup = ("Apple", "Cherry", "Banana", "Apple")
myList = list(myTup)   # Convert tuple to list
myList.remove("Cherry")
myTup = tuple(myList)  # Convert back to tuple
print(myTup)           # Output: ('Apple', 'Banana', 'Apple')

# Deleting a Tuple
del myTup  # Deletes the tuple entirely
# print(myTup)  # Will raise an error because the tuple no longer exists

#------------------------------------------------------------------------------

# Min and Max (Applicable for Numeric or Comparable Elements in a Tuple)
numeric_tuple = (10, 20, 30, 5, 15)
print(min(numeric_tuple))  # Output: 5
print(max(numeric_tuple))  # Output: 30

#------------------------------------------------------------------------------

# Tuple Concatenation
male = ('john', 'paulo', 'king')
female = ('quennie', 'anna', 'jelai')
answer = male + female
print(answer)          # Output: ('john', 'paulo', 'king', 'quennie', 'anna', 'jelai')

#------------------------------------------------------------------------------

# Checking Membership with `in`
name = input("Enter your name: ")
if name in answer:
    print(f"Name {name} is in the answer tuple.")
else:
    print(f"Name {name} is not in the answer tuple.")

# name = "Jeric"
# age = 20
# height = 5.9
# is_Student = True
#
# print(f"Name: {name}")
# print(f"Age: {age}")
# print(f"Height: {height}")
# print(f"is_Student: {is_Student}")
#
# name = 123
# print(f"Updated name: {name}")
# age = age + 1
# print(f"Updated age: {age}")

# x = 5
# y = 3
#
# print("Addition: ", x + y)
# print("Subtraction: ", x - y)
# print("Multiplication: ", x * y)
# print("Division: ", x / y)
#
# print("Integer Division: ", x // y)
# print("Modulus: ", x % y)
# print("Exponentiation: ", x ** y)

# a = 10
# b = 10
#
# print("a == b: ", a == b)
# print("a != b: ", a != b)
# print("a > b: ", a > b)
# print("a < b: ", a < b)
# print("a >= b: ", a >= b)
# print("a <= b: ", a <= b)

# x = 5
# y = 10
#
# print("x > 3 and y < 15: ", x > 3 and y < 15)  #Both True
# print("x > 3 or y < 5: ", x > 3 or y < 5) #Atleast one True


# age = 20
# if age >= 18:
#     print("You are an adult")
# elif age>= 13:
#     print("Your are a teenager")
# else:
#     print("You are a child")

# if age >= 18:
#     print("You are an adult")
# if age>= 13:
#     print("You are a teenager")
# if age>= 30:
#     print("You are a child")


# grade = 'D'
#
# match grade:
#     case 'A':
#         print("Grade A")
#     case 'B':
#         print("Grade B")
#     case 'C':
#         print("Grade C")
#     case _:
#         print("Default")


# for i in range(5, 10): # 5 -> 9
#     print("Iteration", i)

# for i in range(5, 21, 5): # 5, 10
#     print("Iteration", i)


# for i in range(5): # 0 -> 4
#     print("Iteration", i)

# count = 0
# while count < 5:
#     print("Count is: ", count)
#     count += 1


# def my_function():
#     print("My function")
#
# my_function()

# def my_function(fname, lname):
#     print(f"{fname} - {lname}")
#
# my_function("Jeric", "Dela Cruz")

# def my_function(fname, mname, lname):
#     print("The middle name is: ", lname)
#
# my_function(lname = "delacurz", fname= "jeric", mname="juyamag")

# from datetime import datetime
# print(datetime.now().strftime("%Y - %m - %d"))
# print(datetime.now().strftime("%I:%M:%S %p"))

# help("modules")

# #------------------------------------------------------------------------------
# try:
#     age = int(input("Please enter your age: "))
#
#     if age < 18:
#         raise ValueError("You must be 18 or older.")
#     elif age > 100:
#         raise ValueError("Age cannot be greater than 100.")
#     else:
#         print("Thank you for entering a valid age!")
#
# except ValueError as ve:
#     print(f" Execute if age is less than 18: {ve}")
#
# except Exception as e:
#     print(f"A general exception to display: {e}")
#
# else:
#     print("Run when no error occurs")
#
# finally:
#     print("Print anytime, even with/without errors")


# #------------------------------------------------------------------------------
# Lists: []
#     - Ordered: Maintains the order of elements as added
#     - Mutable: Elements can be modified after creation
#     - Allows Duplicates: Can contain multiple identical values

# example_list = [1, 2, 2, "hello", True]
# example_list[3] = "world"
# example_list.append("new")
# example_list.insert(1, "inserted")
# print(example_list)


# #------------------------------------------------------------------------------

# # Tuples: " " or ()
# #     - Ordered: Maintains the order of elements
# #     - Immutable: Cannot be modified after creation
# #     - Allows Duplicates: Can contain multiple identical values

# example_tuple = (1, 2, 2, "hello", True)
# print(example_tuple)
#
# example_list = list(example_tuple)
#
# example_list[0] = 10
# example_list[0] = 10
#
# new_tuple = tuple(example_list)
# print(new_tuple)

# # Notes:
# # - Tuples are useful for data that should not change, like coordinates or constant settings.
# # - A single-element tuple needs a trailing comma, e.g., `single_tuple = (1,)`.

# #------------------------------------------------------------------------------

# # Sets: {}
# #     - Unordered: Does not maintain order
# #     - Mutable: You can add or remove elements (but the set itself is immutable in terms of structure)
# #     - Does NOT Allow Duplicates: Eliminates duplicates automatically

# example_set = {1, 2, 2, "hello", True}
# print(example_set)
# example_set.remove('hello')
# print(example_set)

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
#     "name": "Jeric",
#     "age": 20,
#     "skills": ["Python", "JavaScript"],
#     "age": 35  # Overwrites the earlier "age" key
# }
# print(example_dict)













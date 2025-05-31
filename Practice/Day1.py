# def print_tree(height):
#     for curr_n in range(1, height + 1):
#         print(" " * (height - curr_n), end=" ")
#         print("*" * (curr_n * 2-1), end=" ")
#         print(" " * (height - curr_n))

# print_tree(8)


# ----------------------------------------------------
# choice = True

# while choice:
#     user_int = int(input("Enter a number: "))

#     if(user_int % 2 == 0):
#         print("The number is even")
#     elif(user_int % 2 == 1):
#         print("The number is odd")
#     else:
#         print(f"{user_int} is not a number!")

#     choice = input("Do you want to try again? (y/n): ")
#     if choice != 'Y' and choice != 'y':
#         print("Thank you!")
#         break

# else: 
#     print("Goodbye!")

# ----------------------------------------------------

# convert_time = int(input("Enter the number of seconds: "))

# # 1 hour = 60 minutes = 60 x 60  = 3600seconds
# hours = convert_time // 3600 
# minutes = (convert_time % 3600) // 60
# seconds = convert_time % 60

# print(f"{hours}:{minutes}:{seconds}")

# ----------------------------------------------------

# time_format = int(input("Enter time in 12-hour format to convert: "))

# if time_format % 12 == 0:
#     print(f"{time_format} PM")
# elif time_format % 12 < 12:
#     print(f"{time_format} AM")

# negative, mahirap!

# ----------------------------------------------------

# names_tuple = ["Tanga", "Tamad", "Bobo", "Procastinator", "Dependent"]
# print(f"Before: {names_tuple}")

# names_tuple.insert(1, "Bago")
# print(f"After adding: {names_tuple}")

# names_tuple.remove("Procastinator")
# print(f"After removing: {names_tuple}")

# names_tuple.sort()
# print(f"Sorted: {names_tuple}") 

# names_tuple.append("Lorem")
# print(f"After adding in end: {names_tuple}")

# name_to_check = "Tamad"
# found = False
# for name in names_tuple:
#     if name == name_to_check:
#         found = True
#         break 

# if found:
#     print(f"{name_to_check} exists.")
# else:
#     print(f"{name_to_check} does not exist.")


# ----------------------------------------------------

# choice = True
# sum = 0
# ave_grade = 0

# while choice:
#     for i in range(5):
#         input_grade = int(input("Enter grade: "))
#         sum += input_grade
    
#     ave_grade = sum / 5

#     print(f"Your average grade is {ave_grade}")
#     if ave_grade >= 75:
#         print("You passed!")
#     elif sum < 75:
#         print("You failed!")

#     choice = input("Do you want to try again? (y/n): ")
#     if choice != 'Y' and choice != 'y':
#         print("Thank you!")
#         break

# else: 
#     print("Goodbye!")


# ----------------------------------------------------

# choice = True
# total = 0

# while choice:
#     user_int = input("Enter a number for table: ")

#     for i in range(1, 11):
#         total = int(user_int) * i
#         print(f"{user_int} x {i} = {total}")

#     choice = input("Do you want to try again? (y/n): ")
#     if choice != 'Y' and choice != 'y':
#         print("Thank you!")
#         break

# else: 
#     print("Goodbye!")


# ----------------------------------------------------

# choice = True

# while choice:
#     word = input("Enter a word or phrase: ")

#     reversed_word = ""

#     for i in range(len(word) - 1, -1, -1):  
#         reversed_word += word[i]  

#     print("Reversed word:", reversed_word)


#     choice = input("Do you want to try again? (y/n): ")
#     if choice != 'Y' and choice != 'y':
#         print("Thank you!")
#         break

# else: 
#     print("Goodbye!")

# ----------------------------------------------------

# def is_palindrome(word):
#     reversed_word = ""
    
#     for i in range(len(word) - 1, -1, -1):
#         reversed_word += word[i]
    
#     if word == reversed_word:
#         return True
#     else:
#         return False

# word = input("Enter a word: ")

# if is_palindrome(word):
#     print(f"The word '{word}' is a palindrome.")
# else:
#     print(f"The word '{word}' is not a palindrome.")

# how_many = int(input("Enter how many numbers: "))
# numbers = []

# for i in range(how_many):
#     user_int = int(input(f"Enter number {i + 1}: "))
#     numbers.append(user_int)

# largest = smallest = numbers[0]

# for num in numbers:
#     if num > largest:
#         largest = num
#     if num < smallest:
#         smallest = num
    
# print(f"The largest number is: {largest}")
# print(f"The smallest number is: {smallest}")

# ----------------------------------------------------

# user_int = input("Enter a string: ")
# count = 0
# for i in range(len(user_int)):
#     # if char.lower() in 'aeiou':
#     if user_int[i] == 'a' or user_int[i] == 'e' or user_int[i] == 'i' or user_int[i] == 'o' or user_int[i] == 'u':
#         count += 1
#     if user_int[i] == 'A' or user_int[i] == 'E' or user_int[i] == 'I' or user_int[i] == 'O' or user_int[i] == 'U':
#         count += 1

# print(f"The vowel count is: {count}")

# ----------------------------------------------------

# user_int = input("Enter a string: ")
# find = input("Enter a character: ")
# count = 0

# for i in range(len(user_int)):
#     if user_int[i] == find:
#         count += 1

# print(f"The character '{find}' appears '{count}' times in the string.")

# ----------------------------------------------------

# user_int = input("Enter a number: ")
# sum = 0

# for i in range(len(user_int)):
#     sum += int(user_int[i])

# print(f"The sum of the digits is: {sum}")

# ----------------------------------------------------

# user_int = input("Enter numbers separated by space: ")
# numbers = user_int.split() #space separated 
# total_even = 0
# total_odd = 0 
# total_all = 0 

# for num in numbers:
#     num = int(num)  
#     total_all += num
#     if num % 2 == 0: 
#         total_even += num
#     if num % 2 == 1:
#         total_odd += num
        
# print(f"The sum of even numbers is: {total_even}")
# print(f"The sum of odd numbers is: {total_odd}")
# print(f"The sum of all numbers is: {total_all}")

# ----------------------------------------------------

# user_input = input("Enter numbers separated by space: ")

# numbers = user_input.split() 
# numbers = [int(num) for num in numbers] 

# positive_sum = 0
# negative_sum = 0
# positive_count = 0
# negative_count = 0

# for num in numbers:
#     if num > 0:
#         positive_sum += num  
#         positive_count += 1  
#     elif num < 0:
#         negative_sum += num  
#         negative_count += 1  

# print(f"The sum of positive numbers is: {positive_sum}")
# print(f"The sum of negative numbers is: {negative_sum}")
# print(f"The count of positive numbers is: {positive_count}")
# print(f"The count of negative numbers is: {negative_count}")

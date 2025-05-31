# print("Hello World")
# file = open(file.txt)
# print("Hello World")

# try:
#     file = open('text.txt')
# except Exception:
#     print("The file you are opening is not existing...")
#
# print("Labas na to ng try-except, Continue program...")


# print(x)
# try:
#     print(x)
#     print(y)
# except Exception as ne:
#     print("Error caught! Variable is not defines.")
#     print(ne)
#
# print("Program Continues...")
# sum = 1 + 2
# print(sum)



# myList = ["Amir",1, True,10.35]
# mySet = {1, 2, True}
# z = 0
# try:
#     # file = open("files.txt", "r")
#     # z = int(input("Enter a number: "))
#     x = 10
#     y = 0
#     # quotient = x/y
#     # print(myList[4])
#     print(mySet[2])
# except ValueError as ve:
#     print(f"Invalid input! {ve}")
# except TypeError as te:
#     print(f"Set doesn't have any index! {te}")
# except ZeroDivisionError as zde:
#     print(f"You cannot divide any number by zero! {zde}")
# except IndexError as ie:
#     print(f"You are accessing an index that is out of range! {ie}")
# except Exception as e: # general, this is a parent class
#     print(f"Error! {e}")

# x = 2
# y = 0
# try:
#     print(x/y)
# except ZeroDivisionError:
#     print("Division by zero error:.")
# except NameError as ne:
#     print(f"Variable value is not found. {ne}")
# else:
#     print("Nothing happened.")


# try:
#     x = 1
#     y = 1
#     print(x/y)
# except NameError as ne:
#     print(f"Error occured. {ne}")
# else:
#     print("Nothing happened.")
# finally:
#     print("Bye!")
#
# print("Labas to ng try-except-else-finally block")
# pwede kahit walang else same kahit walang finally
# pero try-catch is always a tandem


# sariling output message na gawa nang programmer
# num = int(input("Enter a number: "))
# if num < 5:
#     raise Exception("The number is less than 5!")
# print("Program continues...")

a = 15
try:
    if a <= 17:
        raise NameError("this is the raise code")
except NameError as ne:
    print(f"Error a. {ne}")
except Exception as e:
    print(f"Error b. {e}")
finally:
    print("Good bye!")
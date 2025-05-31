# while True:
    
#     print("\n[1] If ")
#     print("[2] If Else ")
#     print("[3] If Else If (Elif)")
#     print("[4] Nested If ")
#     print("[5] If with Multiple Conditions (and/or) ")
#     print("[6] Ternary Conditional Operator ")
#     print("[7] Match-Case ")
#     print("[0] Exit")

    
#     choice = int(input("Enter your choice: "))

#     if choice == 0:
#         print("Exiting program.")
#         break  

    
#     if choice == 1:
#         grade = int(input("Enter your grade: "))
#         if grade >= 85:
#             print("Excellent! You have an A.")

#     elif choice == 2:
#         grade = int(input("Enter your grade: "))
#         if grade >= 50:
#             print("You passed")
#         else:
#             print("You failed")

#     elif choice == 3:
#         grade = int(input("Enter your grade: "))
#         if grade >= 85:
#             print("You have an A")
#         elif grade >= 80:
#             print("You have a B+")
#         elif grade >= 70:
#             print("You have a B")
#         else:
#             print("You have a C")

#     elif choice == 4:
#         grade = int(input("Enter your grade: "))
#         if grade >= 50:
#             print("You passed")
#             if grade >= 85:
#                 print("You have an A")
#             elif grade >= 80:
#                 print("You have a B+")
#         else:
#             print("You failed")

#     elif choice == 5:
#         grade = int(input("Enter your grade: "))
#         if grade >= 50 and grade < 70:
#             print("You passed but need improvement.")
#         elif grade >= 70 or grade == 65:
#             print("Good performance!")

#     elif choice == 6:
#         grade = int(input("Enter your grade: "))
#         result = "Passed" if grade >= 50 else "Failed"
#         print(result)

#     elif choice == 7:
grade = int(input("Enter your grade: "))
match grade:
    case 85 | 90 | 95:
        print("You have an A")
    case 80:
        print("You have a B+")
    case _:
        print("You have another grade")

    # else:
    #     print("Invalid choice. Please try again.")

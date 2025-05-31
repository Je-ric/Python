#------------------------------------------------------------------------------
# Program with Inputs, Loop, and Storing Data (Including Tuple)

# Create an empty list, set, dictionary, and tuple to store data
my_list = []
my_set = set()
my_dict = {}
my_tuple = ()

# Ask the user for their choice to start the program
while True:
    print("\nSelect an operation:")
    print("1. Add a value to the list")
    print("2. Add a value to the set")
    print("3. Add a key-value pair to the dictionary")
    print("4. Add a value to the tuple (immutable operation)")
    print("5. View all data in the list")
    print("6. View all data in the set")
    print("7. View all data in the dictionary")
    print("8. View all data in the tuple")
    print("9. Exit")

    choice = input("Enter your choice (1-9): ")

    if choice == "1":
        value = input("Enter a value to add to the list: ")
        my_list.append(value)
        print(f"Value added to the list: {value}")

    elif choice == "2":
        value = input("Enter a value to add to the set: ")
        my_set.add(value)
        print(f"Value added to the set: {value}")

    elif choice == "3":
        key = input("Enter the key for the dictionary: ")
        value = input("Enter the value for the dictionary: ")
        my_dict[key] = value
        print(f"Key-value pair added to the dictionary: {key}: {value}")

    elif choice == "4":
        value = input("Enter a value to add to the tuple: ")
        # Convert the tuple to a list, add the value, and convert it back to a tuple
        my_tuple = my_tuple + (value,)
        print(f"Value added to the tuple: {value}")

    elif choice == "5":
        print("Data in the list:")
        for item in my_list:
            print(item)

    elif choice == "6":
        print("Data in the set:")
        for item in my_set:
            print(item)

    elif choice == "7":
        print("Data in the dictionary:")
        for key, value in my_dict.items():
            print(f"{key}: {value}")

    elif choice == "8":
        print("Data in the tuple:")
        for item in my_tuple:
            print(item)

    elif choice == "9":
        print("Exiting the program. Goodbye!")
        break

    else:
        print("Invalid choice. Please select a valid option.")
        
#------------------------------------------------------------------------------

# Solution 5

# Step 1: Create two tuples
tuple1 = (1, 2, 3, 4, 5)
tuple2 = (6, 7, 8, 9, 10)

# Step 2: Concatenate the tuples
combined_tuple = tuple1 + tuple2

# Step 3: Ask for user input and check membership
user_input = int(input("Enter a number to check: "))

if user_input in combined_tuple:
    print(f"The number {user_input} is in the tuple.")
else:
    print(f"The number {user_input} is not in the tuple.")

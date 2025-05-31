# Solution 3

# Step 1: Create two tuples
male_names = ('john', 'paulo', 'king')
female_names = ('quennie', 'anna', 'jelai')

# Step 2: Input a name
user_name = input("Enter a name to check: ")

# Step 3: Check if the name exists in either tuple
if user_name in male_names:
    print(f"{user_name} is in the male names tuple.")
elif user_name in female_names:
    print(f"{user_name} is in the female names tuple.")
else:
    print(f"{user_name} is not in either tuple.")

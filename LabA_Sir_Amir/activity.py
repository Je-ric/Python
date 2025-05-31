from random import choice

first_names = ['Jeric', 'Franz', 'Ejay', 'Ronnel', 'Lorenz', 'John']
middle_names = ['Juyamag', 'Adriano', 'Ponse']
last_names = ['Dela Cruz', 'Basinga', 'Eda', 'Baldovino', 'Villamor']

while True:
    first_name = choice(first_names)
    middle_name = choice(middle_names)
    last_name = choice(last_names)
    
    full_name = f"{first_name} {middle_name} {last_name}"

    print(f"Congratulations on your new name: {full_name}")
    
    choice_input = input("Do you want to try again? (Y/N): ")
    if choice_input != 'Y' and choice_input != 'y':
        print("Thank you!")
        break

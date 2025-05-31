#------------------------------------------------------------------------------
# Birthday Reminder System

from datetime import datetime

birthdays = {}

def add_birthday():
    name = input("Enter the person's name: ")
    birthday_input = input(f"Enter {name}'s birthday (YYYY-MM-DD): ")
    birthday = datetime.strptime(birthday_input, "%Y-%m-%d")
    birthdays[name] = birthday
    print(f"Birthday for {name} added.")

def check_upcoming_birthday():
    today = datetime.today()
    upcoming_birthdays = []
    for name, birthday in birthdays.items():
        birthday_this_year = birthday.replace(year=today.year)
        if birthday_this_year >= today:
            upcoming_birthdays.append((name, birthday_this_year))

    if upcoming_birthdays:
        print("\nUpcoming Birthdays:")
        for name, birthday in sorted(upcoming_birthdays, key=lambda x: x[1]):
            print(f"{name}: {birthday.strftime('%Y-%m-%d')}")
    else:
        print("No upcoming birthdays.")

while True:
    print("\nBirthday Reminder System")
    print("1. Add Birthday")
    print("2. Check Upcoming Birthdays")
    print("3. Exit")

    choice = input("Choose an option: ")

    if choice == '1':
        add_birthday()
    elif choice == '2':
        check_upcoming_birthday()
    elif choice == '3':
        print("Exiting the system.")
        break
    else:
        print("Invalid choice. Please try again.")
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Weekly Planner

from datetime import datetime

# Initialize an empty dictionary for the weekly planner
week_planner = {}

def get_day_of_week():
    day = input("Enter the day of the week (Monday, Tuesday, etc.): ").capitalize()
    return day

while True:
    print("\nWeekly Planner")
    print("1. Add Task")
    print("2. View Schedule")
    print("3. Exit")

    choice = input("Choose an option: ")

    if choice == '1':
        day = get_day_of_week()
        task = input(f"Enter the task for {day}: ")
        week_planner[day] = task
        print(f"Task for {day} added.")
    elif choice == '2':
        print("\nYour Weekly Schedule:")
        if not week_planner:
            print("No tasks scheduled yet.")
        else:
            for day, task in week_planner.items():
                print(f"{day}: {task}")
    elif choice == '3':
        print("Exiting the planner.")
        break
    else:
        print("Invalid choice. Please try again.")
#------------------------------------------------------------------------------

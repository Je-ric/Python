#------------------------------------------------------------------------------
# Employee Attendance Tracker

from datetime import datetime

attendance = {}

def mark_attendance():
    name = input("Enter employee name: ")
    date_input = input("Enter the date (YYYY-MM-DD): ")
    date = datetime.strptime(date_input, "%Y-%m-%d")
    
    if name in attendance:
        attendance[name].append(date)
    else:
        attendance[name] = [date]
    print(f"Attendance for {name} on {date.strftime('%Y-%m-%d')} marked.")

def view_attendance():
    if not attendance:
        print("No attendance records available.")
    else:
        for name, dates in attendance.items():
            print(f"\n{name}'s Attendance:")
            for date in dates:
                print(f"- {date.strftime('%Y-%m-%d')}")

while True:
    print("\n1. Mark Attendance")
    print("2. View Attendance")
    print("3. Exit")
    
    choice = input("Choose an option: ")
    
    if choice == '1':
        mark_attendance()
    elif choice == '2':
        view_attendance()
    elif choice == '3':
        print("Exiting...")
        break
    else:
        print("Invalid choice, please try again.")
#------------------------------------------------------------------------------

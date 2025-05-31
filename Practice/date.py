#------------------------------------------------------------------------------
# Program with Date and Time Handling

from datetime import datetime

# Get the current date and time
current_datetime = datetime.now()
print(f"Current date and time: {current_datetime}")

# Get only the current date
current_date = current_datetime.date()
print(f"Current date: {current_date}")

# Get only the current time
current_time = current_datetime.time()
print(f"Current time: {current_time}")

# Ask the user to input a future date
future_date_input = input("Enter a future date (YYYY-MM-DD): ")

# Convert the user input into a date object
try:
    future_date = datetime.strptime(future_date_input, "%Y-%m-%d").date()
    print(f"Your future date: {future_date}")

    # Calculate the difference between the future date and the current date
    date_difference = future_date - current_date
    print(f"The difference between the current date and your future date is {date_difference.days} days.")
except ValueError:
    print("Invalid date format. Please use the format YYYY-MM-DD.")

#------------------------------------------------------------------------------

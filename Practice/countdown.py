#------------------------------------------------------------------------------
# Event Countdown Timer

from datetime import datetime

event_date_input = input("Enter the event date (YYYY-MM-DD): ")
event_date = datetime.strptime(event_date_input, "%Y-%m-%d")

today = datetime.today()

if event_date < today:
    print("The event date is in the past!")
else:
    days_left = (event_date - today).days
    print(f"The event is in {days_left} days.")
#------------------------------------------------------------------------------

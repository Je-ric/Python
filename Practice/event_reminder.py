#------------------------------------------------------------------------------
# Event Reminder with Countdown

from datetime import datetime
import time

def get_event_details():
    event_name = input("Enter the event name: ")
    event_date_input = input("Enter the event date (YYYY-MM-DD HH:MM): ")
    event_date = datetime.strptime(event_date_input, "%Y-%m-%d %H:%M")
    return event_name, event_date

def countdown(event_date):
    while True:
        today = datetime.now()
        time_left = event_date - today

        if time_left.total_seconds() <= 0:
            print("The event is now!")
            break
        else:
            print(f"Time left: {time_left}")
            time.sleep(60)  # Wait for 1 minute before checking again

event_name, event_date = get_event_details()
print(f"Reminder set for {event_name} on {event_date}.")
countdown(event_date)
#------------------------------------------------------------------------------

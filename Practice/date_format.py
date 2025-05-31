#------------------------------------------------------------------------------
# Date Format Converter

from datetime import datetime

input_date = input("Enter a date (YYYY-MM-DD): ")
date_object = datetime.strptime(input_date, "%Y-%m-%d")

# Convert to a different format
formatted_date = date_object.strftime("%d-%m-%Y")
print(f"Formatted Date: {formatted_date}")
#------------------------------------------------------------------------------

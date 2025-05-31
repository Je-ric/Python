#------------------------------------------------------------------------------
# Date Difference Calculator

from datetime import datetime

date1_input = input("Enter the first date (YYYY-MM-DD): ")
date1 = datetime.strptime(date1_input, "%Y-%m-%d")

date2_input = input("Enter the second date (YYYY-MM-DD): ")
date2 = datetime.strptime(date2_input, "%Y-%m-%d")

date_diff = abs(date2 - date1)
print(f"The difference between the two dates is {date_diff.days} days.")
#------------------------------------------------------------------------------

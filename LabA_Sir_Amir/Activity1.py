#  Name: Jeric J. Dela Cruz
#  Activity Number: 1
#  Year & Section: BSIT_3-2

emp_name = input("Employee name: ")
num_hours = int(input("Enter number of hours: "))  
sss = int(input("SSS contribution: "))  
phil_health = int(input("Phil Health: "))  
house_loan = int(input("Housing loan: "))  

rate_per_hour = 500  
tax_rate = 0.10      
gross_salary = num_hours * rate_per_hour
tax = gross_salary * tax_rate
deductions = sss + phil_health + house_loan + tax
net_salary = gross_salary - deductions

print("\n========== PAYSLIP ==========")
print("========== EMPLOYEE INFORMATION ==========")
print(f"Employee Name: {emp_name}")
print(f"Rendered Hours: {num_hours}")
print(f"Rate per Hour: {rate_per_hour}")
print(f"Gross Salary: {gross_salary:.2f}")

print("\n========== DEDUCTIONS ==========")
print(f"SSS: {sss}")
print(f"PhilHealth: {phil_health}")
print(f"Other Loan: {house_loan}")
print(f"Tax: {tax:.2f}")
print(f"Total Deductions: {deductions:.2f}")
print(f"Net Salary: {net_salary:.2f}")

print("\n========== DEDUCTIONS ==========")
print("SSS: {}".format(sss))
print("PhilHealth: {}".format(phil_health))
print("Other Loan: {}".format(house_loan))
print("Tax: {:.2f}".format(tax))
print("Total Deductions: {:.2f}".format(deductions))
print("Net Salary: {:.2f}".format(net_salary))

print("\n========== DEDUCTIONS ==========")
print("SSS: %d" % sss)
print("PhilHealth: %d" % phil_health)
print("Other Loan: %d" % house_loan)
print("Tax: %.2f" % tax)
print("Total Deductions: %.2f" % deductions)
print("Net Salary: %.2f" % net_salary)

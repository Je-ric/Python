#------------------------------------------------------------------------------
# Bank Account System

class BankAccount:
    def __init__(self, account_holder, balance=0):
        self.account_holder = account_holder
        self.balance = balance

    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            print(f"Deposited: {amount}. New balance: {self.balance}.")
        else:
            print("Amount must be positive.")

    def withdraw(self, amount):
        if amount <= self.balance and amount > 0:
            self.balance -= amount
            print(f"Withdrew: {amount}. New balance: {self.balance}.")
        elif amount > self.balance:
            print("Insufficient balance.")
        else:
            print("Amount must be positive.")

    def check_balance(self):
        print(f"Balance: {self.balance}")

# Main program
name = input("Enter your name: ")
account = BankAccount(name)

while True:
    print("\nBank Account Menu:")
    print("1. Deposit")
    print("2. Withdraw")
    print("3. Check Balance")
    print("4. Exit")

    choice = input("Choose an option: ")

    if choice == '1':
        amount = float(input("Enter the deposit amount: "))
        account.deposit(amount)
    elif choice == '2':
        amount = float(input("Enter the withdrawal amount: "))
        account.withdraw(amount)
    elif choice == '3':
        account.check_balance()
    elif choice == '4':
        break
    else:
        print("Invalid choice. Please try again.")
#------------------------------------------------------------------------------

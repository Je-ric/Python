#------------------------------------------------------------------------------
# Simple Inventory System

inventory = {}

def add_item():
    name = input("Enter the name of the item: ")
    quantity = int(input(f"Enter the quantity of {name}: "))
    inventory[name] = inventory.get(name, 0) + quantity
    print(f"Added {quantity} {name}(s).")

def remove_item():
    name = input("Enter the name of the item to remove: ")
    if name in inventory:
        quantity = int(input(f"Enter the quantity to remove of {name}: "))
        if quantity <= inventory[name]:
            inventory[name] -= quantity
            print(f"Removed {quantity} {name}(s).")
        else:
            print(f"Not enough {name} in stock.")
    else:
        print(f"{name} is not in the inventory.")

def view_inventory():
    if inventory:
        print("\nInventory:")
        for name, quantity in inventory.items():
            print(f"{name}: {quantity}")
    else:
        print("Inventory is empty.")

while True:
    print("\nInventory System")
    print("1. Add Item")
    print("2. Remove Item")
    print("3. View Inventory")
    print("4. Exit")

    choice = input("Choose an option: ")
    if choice == '1':
        add_item()
    elif choice == '2':
        remove_item()
    elif choice == '3':
        view_inventory()
    elif choice == '4':
        break
    else:
        print("Invalid choice. Please try again.")
#------------------------------------------------------------------------------

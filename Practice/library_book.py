#------------------------------------------------------------------------------
# Library Book Tracking System

from datetime import datetime

books = set()

def add_book():
    book_name = input("Enter the book name: ")
    books.add(book_name)
    print(f"Book '{book_name}' added to the library.")

def view_books():
    if not books:
        print("No books in the library.")
    else:
        print("Books in the library:")
        for book in books:
            print(book)

def remove_book():
    book_name = input("Enter the book name to remove: ")
    if book_name in books:
        books.remove(book_name)
        print(f"Book '{book_name}' removed from the library.")
    else:
        print(f"Book '{book_name}' not found in the library.")

while True:
    print("\n1. Add Book")
    print("2. View Books")
    print("3. Remove Book")
    print("4. Exit")
    
    choice = input("Choose an option: ")
    
    if choice == '1':
        add_book()
    elif choice == '2':
        view_books()
    elif choice == '3':
        remove_book()
    elif choice == '4':
        print("Exiting...")
        break
    else:
        print("Invalid choice, please try again.")
#------------------------------------------------------------------------------

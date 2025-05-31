#------------------------------------------------------------------------------
# Task Management System

tasks = []

def add_task():
    task = input("Enter a new task: ")
    tasks.append({'task': task, 'completed': False})
    print(f"Task added: {task}")

def complete_task():
    task_number = int(input("Enter the task number to mark as complete: "))
    if 0 < task_number <= len(tasks):
        tasks[task_number-1]['completed'] = True
        print(f"Task {task_number} marked as completed.")
    else:
        print("Invalid task number.")

def view_tasks():
    if tasks:
        print("\nTask List:")
        for i, task in enumerate(tasks, 1):
            status = "Completed" if task['completed'] else "Pending"
            print(f"{i}. {task['task']} - {status}")
    else:
        print("No tasks in the list.")

while True:
    print("\nTask Management System")
    print("1. Add Task")
    print("2. Complete Task")
    print("3. View Tasks")
    print("4. Exit")

    choice = input("Choose an option: ")

    if choice == '1':
        add_task()
    elif choice == '2':
        complete_task()
    elif choice == '3':
        view_tasks()
    elif choice == '4':
        break
    else:
        print("Invalid choice. Please try again.")
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Student Grade Management System

def get_letter_grade(average):
    if average >= 90:
        return 'A'
    elif average >= 80:
        return 'B'
    elif average >= 70:
        return 'C'
    elif average >= 60:
        return 'D'
    else:
        return 'F'

students = {}
num_students = int(input("Enter the number of students: "))

for _ in range(num_students):
    name = input("\nEnter student's name: ")
    grades = []
    num_grades = int(input(f"How many grades for {name}? "))
    
    for i in range(num_grades):
        grade = float(input(f"Enter grade {i+1}: "))
        grades.append(grade)
    
    average = sum(grades) / len(grades)
    letter_grade = get_letter_grade(average)
    students[name] = {'grades': grades, 'average': average, 'letter_grade': letter_grade}

print("\nStudent Report:")
for name, info in students.items():
    print(f"{name}: Grades: {info['grades']}, Average: {info['average']:.2f}, Letter Grade: {info['letter_grade']}")
#------------------------------------------------------------------------------

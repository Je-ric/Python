#------------------------------------------------------------------------------ 
# Set CRUD Operations
my_set = {10, 20, 30, 40, 50}
print("Does 30 exist in the set?", 30 in my_set)
my_set.add(60)
print("Set after adding 60:", my_set)
my_set.remove(40)
print("Set after removing 40:", my_set)
my_set.clear()
print("Set after clearing all elements:", my_set)
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Dictionary CRUD Operations
my_dict = {"name": "John", "age": 25, "city": "New York"}
print("Name:", my_dict["name"])
print("Age:", my_dict["age"])
my_dict["age"] = 26
print("Updated dictionary:", my_dict)
del my_dict["city"]
print("Dictionary after deleting 'city':", my_dict)
my_dict.clear()
print("Dictionary after clearing all elements:", my_dict)
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# List CRUD Operations
my_list = [10, 20, 30, 40, 50]
print("Element at index 2:", my_list[2])
my_list[2] = 35
print("List after updating index 2:", my_list)
my_list.remove(40)
print("List after removing 40:", my_list)
my_list.clear()
print("List after clearing all elements:", my_list)
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Tuple CRUD Operations
my_tuple = (10, 20, 30, 40, 50)
print("Element at index 3:", my_tuple[3])
my_list = list(my_tuple)
my_list.append(60)
my_tuple = tuple(my_list)
print("Tuple after adding 60:", my_tuple)
my_list = list(my_tuple)
my_list.remove(30)
my_tuple = tuple(my_list)
print("Tuple after removing 30:", my_tuple)
my_tuple = ()
print("Tuple after clearing all elements:", my_tuple)
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Combined CRUD Operations
my_set = {10, 20, 30, 40, 50}
my_tuple = (10, 20, 30, 40, 50)
my_list = [10, 20, 30, 40, 50]
my_dict = {"name": "John", "age": 25, "city": "New York"}
print("Check if 30 exists in set:", 30 in my_set)
print("Access tuple element at index 2:", my_tuple[2])
print("Access list element at index 4:", my_list[4])
print("Access dictionary key 'name':", my_dict["name"])
my_set.add(60)
my_tuple = tuple(list(my_tuple) + [60])
my_list[2] = 35
my_dict["age"] = 26
print("Updated set:", my_set)
print("Updated tuple:", my_tuple)
print("Updated list:", my_list)
print("Updated dictionary:", my_dict)
my_set.remove(40)
my_tuple = tuple([elem for elem in my_tuple if elem != 40])
my_list.remove(40)
del my_dict["city"]
print("Set after deletion:", my_set)
print("Tuple after deletion:", my_tuple)
print("List after deletion:", my_list)
print("Dictionary after deletion:", my_dict)
#------------------------------------------------------------------------------

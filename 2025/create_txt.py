# Let's create a simple notes.txt file containing all the ES6 and React basics explained so far,
# plus a short section introducing React and why to use it, written in simple words.

notes_content = """
Dito yung content ng notes.
"""

# Save to a text file
file_path = "/mnt/data/notes.txt"
with open(file_path, "w") as f:
    f.write(notes_content)

file_path

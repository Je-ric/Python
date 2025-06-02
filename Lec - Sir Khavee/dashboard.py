from bokeh.plotting import figure, show, output_file
from bokeh.layouts import gridplot
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.palettes import Category20c
from bokeh.palettes import Category10
from bokeh.transform import cumsum
import pandas as pd
import numpy as np
from math import pi

# Load the CSV data
file_path = "youmanitarian_user_data.csv"
df = pd.read_csv(file_path)

# Prepare output file
output_file("youmanitarian_dashboard.html")

# 1. Total users count
total_users = len(df)

# 2. Gender distribution (bar chart)
gender_counts = df['gender'].value_counts()
gender_source = ColumnDataSource(data=dict(gender=gender_counts.index.tolist(), count=gender_counts.values))

gender_fig = figure(x_range=gender_counts.index.tolist(), height=300, title="Gender Distribution",
                    toolbar_location=None, tools="")
gender_fig.vbar(x='gender', top='count', width=0.9, source=gender_source)
gender_fig.xgrid.grid_line_color = None
gender_fig.y_range.start = 0

# 3. Active vs Inactive (pie chart)
status_counts = df['status'].value_counts()
status_data = pd.Series(status_counts).reset_index(name='value').rename(columns={'index': 'status'})
status_data['angle'] = status_data['value']/status_data['value'].sum() * 2 * pi
# status_data['color'] = Category20c[len(status_data)]
status_data['color'] = Category10[10][:len(status_data)]

status_fig = figure(height=300, title="User Status (Active vs Inactive)", toolbar_location=None,
                    tools="hover", tooltips="@status: @value", x_range=(-0.5, 1.0))
status_fig.wedge(x=0, y=1, radius=0.4, 
                 start_angle=cumsum('angle', include_zero=True), end_angle=cumsum('angle'),
                 line_color="white", fill_color='color', legend_field='status', source=status_data)
status_fig.axis.visible = False
status_fig.grid.grid_line_color = None

# 4. Program participation (bar chart)
program_counts = df['programName'].value_counts()
program_source = ColumnDataSource(data=dict(program=program_counts.index.tolist(), count=program_counts.values))

program_fig = figure(x_range=program_counts.index.tolist(), height=300, title="Program Participation",
                     toolbar_location=None, tools="")
program_fig.vbar(x='program', top='count', width=0.9, source=program_source)
program_fig.xaxis.major_label_orientation = pi/4
program_fig.y_range.start = 0

# 5. Average rating distribution (histogram)
# The column in the CSV is 'averageRating' but with empty strings, convert to numeric, coercing errors to NaN
df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
rating_hist, rating_edges = np.histogram(df['averageRating'].dropna(), bins=5, range=[1, 5])
rating_fig = figure(title='Rating Distribution', height=300)
rating_fig.quad(top=rating_hist, bottom=0, left=rating_edges[:-1], right=rating_edges[1:], fill_color="navy", line_color="white")

# 6. Total donations by location (bar chart)
donations_by_location = df.groupby('location')['donation'].sum().sort_values(ascending=False)
donation_fig = figure(x_range=donations_by_location.index.tolist(), height=300, title="Total Donations by Location",
                      toolbar_location=None, tools="")
donation_fig.vbar(x=donations_by_location.index.tolist(), top=donations_by_location.values, width=0.9)
donation_fig.xaxis.major_label_orientation = pi/4
donation_fig.y_range.start = 0

# 7. Volunteer vs Non-volunteer (bar chart)
volunteer_counts = df['isVolunteer'].value_counts()
volunteer_source = ColumnDataSource(data=dict(
    volunteer_status = volunteer_counts.index.map({True: 'Volunteer', False: 'Not Volunteer'}).tolist(),
    count = volunteer_counts.values
))
volunteer_fig = figure(x_range=volunteer_source.data['volunteer_status'], height=300,
                       title="Volunteer Status", toolbar_location=None, tools="")
volunteer_fig.vbar(x='volunteer_status', top='count', width=0.9, source=volunteer_source)
volunteer_fig.y_range.start = 0

# 8. Role Distribution (bar chart)
# Only members have user roles, so filter non-empty roles
role_counts = df[df['userRole'] != '']['userRole'].value_counts()
role_source = ColumnDataSource(data=dict(role=role_counts.index.tolist(), count=role_counts.values))

role_fig = figure(x_range=role_counts.index.tolist(), height=300, title="User Roles",
                  toolbar_location=None, tools="")
role_fig.vbar(x='role', top='count', width=0.9, source=role_source)
role_fig.xaxis.major_label_orientation = pi/4
role_fig.y_range.start = 0

# 9. Donations by Role (bar chart)
donations_by_role = df.groupby('userRole')['donation'].sum().sort_values(ascending=False)
donations_by_role = donations_by_role[donations_by_role.index != '']  # exclude empty roles
donation_role_fig = figure(x_range=donations_by_role.index.tolist(), height=300, title="Donations by Role",
                           toolbar_location=None, tools="")
donation_role_fig.vbar(x=donations_by_role.index.tolist(), top=donations_by_role.values, width=0.9)
donation_role_fig.xaxis.major_label_orientation = pi/4
donation_role_fig.y_range.start = 0

# 10. Ratings by Program (bar chart)
ratings_by_program = df.groupby('programName')['averageRating'].mean().sort_values(ascending=False)
ratings_by_program = ratings_by_program.dropna()
rating_prog_fig = figure(x_range=ratings_by_program.index.tolist(), height=300, title="Average Rating per Program",
                         toolbar_location=None, tools="")
rating_prog_fig.vbar(x=ratings_by_program.index.tolist(), top=ratings_by_program.values, width=0.9)
rating_prog_fig.xaxis.major_label_orientation = pi/4
rating_prog_fig.y_range.start = 0

# Combine all plots into a grid layout
dashboard = gridplot([
    [gender_fig, status_fig],
    [program_fig, rating_fig],
    [donation_fig, volunteer_fig],
    [role_fig, donation_role_fig],
    [rating_prog_fig]
], sizing_mode='scale_width')

# Show the dashboard
show(dashboard)

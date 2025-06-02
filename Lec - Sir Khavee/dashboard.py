import pandas as pd
from bokeh.layouts import column, row
from bokeh.models import ColumnDataSource, Select
from bokeh.plotting import figure, curdoc
from bokeh.io import output_file, show

# Load data
df = pd.read_csv("students.csv")

# Create ColumnDataSource
source = ColumnDataSource(df)

# Plot 1: Social Media vs Sleep
p1 = figure(title="Social Media Hours vs. Sleep Hours", x_axis_label="Hours on Social Media", y_axis_label="Hours of Sleep")
p1.circle(x="HoursOnSocialMedia", y="HoursOfSleep", source=source, size=8, color="navy", alpha=0.5)

# Plot 2: Average Mental Health Rating per Country
avg_rating = df.groupby("Country")["MentalHealthRating"].mean().reset_index()
source2 = ColumnDataSource(avg_rating)

p2 = figure(x_range=avg_rating["Country"], title="Average Mental Health Rating by Country", x_axis_label="Country", y_axis_label="Rating", height=350)
p2.vbar(x="Country", top="MentalHealthRating", width=0.5, source=source2, color="orange")

# Output file (for static HTML)
output_file("dashboard.html")

# Layout
dashboard = column(p1, p2)

# Show the dashboard
show(dashboard)

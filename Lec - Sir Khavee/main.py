from bokeh.plotting import curdoc
from bokeh.models import CheckboxGroup, ColumnDataSource, Div
from bokeh.layouts import column, row, layout
from data_loader import load_data
from bokeh.layouts import gridplot
from bokeh.plotting import output_file, show
import pandas as pd
# Import all chart functions
from charts.gender_distribution import gender_distribution
from charts.status_pie import status_pie
from charts.program_participation import program_participation
from charts.rating_distribution import rating_distribution
from charts.donation_by_location import donation_by_location
from charts.volunteer_status import volunteer_status
from charts.role_distribution import role_distribution
from charts.donation_by_role import donation_by_role
from charts.rating_by_program import rating_by_program

from charts.chart1_membership_vs_volunteer import chart as chart1
from charts.chart2_application_status import chart as chart2
from charts.chart3_age_group import chart as chart3
from charts.chart4_avg_hours import chart as chart4
from charts.chart5_payments_by_location import chart as chart5
from charts.chart6_skill_distribution import chart as chart6
from charts.chart7_donation_vs_payment import chart as chart7
from charts.chart8_rating_by_role import chart as chart8
from charts.chart9_active_volunteers import chart as chart9
from charts.chart10_membership_trends import chart as chart10

# Load the data
df = load_data()

# Chart mapping
chart_functions = {
    "Gender Distribution": gender_distribution,
    "Status Pie": status_pie,
    "Program Participation": program_participation,
    "Rating Distribution": rating_distribution,
    "Donation by Location": donation_by_location,
    "Volunteer Status": volunteer_status,
    "Role Distribution": role_distribution,
    "Donation by Role": donation_by_role,
    "Rating by Program": rating_by_program,
    "Membership vs Volunteer": chart1,
    "Application Status": chart2,
    "Age Group Distribution": chart3,
    "Avg Hours per Program": chart4,
    "Payments by Location": chart5,
    "Skill Distribution": chart6,
    "Donation vs Payment": chart7,
    "Rating by Role": chart8,
    "Active Volunteers": chart9,
    "Membership Trends": chart10,
}

# Checkbox for selecting which charts to show
checkbox = CheckboxGroup(labels=list(chart_functions.keys()), active=list(range(len(chart_functions))))

# Div title
# title_div = Div(text="<h2>Youmanitarian Dashboard</h2>", style={"text-align": "center"})
title_div = Div(text="Youmanitarian Dashboard", styles={"text-align": "center", "font-size": "20px", "font-weight": "bold", "margin-bottom": "20px"})


# Container for charts
chart_column = column()

def update_dashboard(attr, old, new):
    selected_labels = [checkbox.labels[i] for i in checkbox.active]
    selected_charts = [chart_functions[label](df) for label in selected_labels]
    chart_column.children = selected_charts

# Initial chart rendering
update_dashboard(None, None, None)

# Attach update callback
checkbox.on_change("active", update_dashboard)

# Layout: left (controls), right (charts) - 30/70 split
controls = column(Div(text="<b>Select Charts:</b>"), checkbox, width=300)
dashboard_layout = row(controls, chart_column, sizing_mode="stretch_both")

# Add to the document
curdoc().add_root(column(title_div, dashboard_layout))
curdoc().title = "Youmanitarian Dashboard"

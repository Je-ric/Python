from bokeh.io import curdoc
from bokeh.layouts import column, row, gridplot
from bokeh.models import CheckboxGroup, Button, Div
from data_loader import load_data

# Chart imports
from charts.gender_distribution import gender_distribution
from charts.status_pie import status_pie
from charts.program_participation import program_participation
from charts.rating_distribution import rating_distribution
from charts.donation_by_location import donation_by_location
from charts.volunteer_status import volunteer_status
from charts.role_distribution import role_distribution
from charts.donation_by_role import donation_by_role
from charts.rating_by_program import rating_by_program

# Load Data
df = load_data()

# Chart mapping
chart_functions = {
    "Gender Distribution": gender_distribution,
    "User Status Pie": status_pie,
    "Program Participation": program_participation,
    "Rating Distribution": rating_distribution,
    "Donations by Location": donation_by_location,
    "Volunteer Status": volunteer_status,
    "Role Distribution": role_distribution,
    "Donations by Role": donation_by_role,
    "Rating by Program": rating_by_program,
}

# Checkbox for selecting charts
checkboxes = CheckboxGroup(labels=list(chart_functions.keys()), active=list(range(len(chart_functions))))

# Layout placeholder
plot_area = column()

# Callback to update dashboard
def update_dashboard():
    selected = [checkboxes.labels[i] for i in checkboxes.active]
    plots = [chart_functions[label](df) for label in selected]
    layout = gridplot([plots[i:i+2] for i in range(0, len(plots), 2)], sizing_mode='scale_width')
    plot_area.children = [layout]

# Button to trigger update
update_button = Button(label="Update Dashboard", button_type="success")
update_button.on_click(update_dashboard)

# Initial display
update_dashboard()

# Final layout
curdoc().add_root(column(
    Div(text="<h2>Youmanitarian Analytics Dashboard</h2>"),
    row(checkboxes, update_button),
    plot_area
))
curdoc().title = "Youmanitarian Dashboard"

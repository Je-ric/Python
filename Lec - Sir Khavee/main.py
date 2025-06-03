from bokeh.plotting import curdoc
from bokeh.models import CheckboxGroup, ColumnDataSource, Div
from bokeh.layouts import column, row
from data_loader import load_data

# Import chart functions
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

# Checkbox with no initial selection
checkbox = CheckboxGroup(
    labels=list(chart_functions.keys()),
    active=[]
)

# Chart container
chart_column = column()

# Callback function
def update_dashboard(attr, old, new):
    selected_labels = [checkbox.labels[i] for i in checkbox.active]
    selected_charts = [chart_functions[label](df) for label in selected_labels]
    chart_column.children = selected_charts

# Attach the callback
checkbox.on_change("active", update_dashboard)


title_div = Div(
    text="""
        <div style='text-align:center;'>
            <h1 style='color:#ffb51b; font-size:28px; font-weight:bold; margin-bottom:15px;'>
                Youmanitarian International
            </h1>
        </div>
    """
)


# Styled control section title
controls_title = Div(
    text="<b style='color:#333;'>Select Charts:</b>",
    styles={"margin-bottom": "10px"}
)

sidebar = column(
    controls_title,
    checkbox,
    width=300,
    sizing_mode="stretch_height",
    styles={
        "background-color": "#fcfcfc",  # light grey tone
        "border-right": "2px solid #ffb51b",  # right divider line
        "padding": "15px",
        "box-sizing": "border-box",
        "height": "100vh",
        "overflow": "auto",
        "font-size": "20px",
        "font-weight": "600",
        "font-family": "Segoe UI, sans-serif",
        "color": "#333"
    }
)

# Apply overall layout
chart_area = column(
    title_div,
    chart_column,
    sizing_mode="stretch_both",
    styles={
        "padding-left": "20px"  
    }
)

# Final layout with sidebar and chart area
dashboard_layout = row(
    sidebar,
    chart_area,
    sizing_mode="stretch_both"
)

curdoc().add_root(dashboard_layout)
curdoc().title = "Youmanitarian Dashboard"

# Inject custom CSS for styling
curdoc().template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Youmanitarian Dashboard</title>
    <style>
    </style>
</head>
<body>
    {{ bokeh_css }}
    {{ bokeh_js }}
    {{ plot_div | safe }}
    {{ plot_script | safe }}
</body>
</html>
"""


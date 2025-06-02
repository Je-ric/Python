from bokeh.plotting import figure, show, output_file
from bokeh.layouts import gridplot
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.palettes import Category10, Category20c
from bokeh.transform import factor_cmap
import pandas as pd
import numpy as np
from math import pi

# Load data
file_path = "youmanitarian_user_data.csv"
df = pd.read_csv(file_path)

# Convert dateJoined to datetime
df['dateJoined'] = pd.to_datetime(df['dateJoined'], errors='coerce')

# Output file for the new dashboard
output_file("youmanitarian_additional_analytics.html")

# --- 1. Membership Status vs Volunteer Status ---
df['membershipStatus'] = np.where(df['isMember'], 'Member', 'Not Member')
df['volunteerStatus'] = np.where(df['isVolunteer'], 'Volunteer', 'Not Volunteer')

membership_volunteer_counts = df.groupby(['membershipStatus', 'volunteerStatus']).size().reset_index(name='count')

membership_volunteer_pivot = membership_volunteer_counts.pivot(index='membershipStatus', columns='volunteerStatus', values='count').fillna(0)
membership_volunteer_pivot = membership_volunteer_pivot[['Volunteer', 'Not Volunteer']]  # order columns

# Plot stacked bar chart
membership_statuses = membership_volunteer_pivot.index.tolist()
volunteer_statuses = membership_volunteer_pivot.columns.tolist()

data = {'membershipStatus': membership_statuses}
for vs in volunteer_statuses:
    data[vs] = membership_volunteer_pivot[vs].values

source = ColumnDataSource(data=data)

colors = Category10[10][:len(volunteer_statuses)]
p1 = figure(x_range=membership_statuses, height=300, title="Membership Status vs Volunteer Status",
            toolbar_location=None, tools="")

# Build bottoms for stacking
bottoms = np.zeros(len(membership_statuses))

p1 = figure(x_range=membership_statuses, height=300, title="Membership Status vs Volunteer Status",
            toolbar_location=None, tools="")

for i, vs in enumerate(volunteer_statuses):
    top = data[vs]
    # Create a dict for each render call
    cds = ColumnDataSource(data=dict(
        membershipStatus=membership_statuses,
        top=top,
        bottom=bottoms
    ))
    p1.vbar(x='membershipStatus', top='top', bottom='bottom', width=0.9,
            color=colors[i], legend_label=vs, source=cds)
    bottoms += top

p1.y_range.start = 0
p1.xgrid.grid_line_color = None
p1.axis.minor_tick_line_color = None
p1.outline_line_color = None
p1.legend.location = "top_right"
p1.legend.orientation = "horizontal"

# --- 2. Volunteer Application Status Distribution ---
app_status_counts = df['volunteerApplicationStatus'].fillna('No Application').value_counts()
app_status_source = ColumnDataSource(data=dict(
    status=app_status_counts.index.tolist(),
    count=app_status_counts.values
))

p2 = figure(x_range=app_status_counts.index.tolist(), height=300, title="Volunteer Application Status Distribution",
            toolbar_location=None, tools="")
p2.vbar(x='status', top='count', width=0.9, source=app_status_source)
p2.xaxis.major_label_orientation = pi/4
p2.y_range.start = 0

# --- 3. Age Group Distribution ---
bins = [17, 25, 35, 45, 55, 100]
labels = ['18-25', '26-35', '36-45', '46-55', '56+']
df['ageGroup'] = pd.cut(df['age'], bins=bins, labels=labels)

age_group_counts = df['ageGroup'].value_counts().sort_index()
age_source = ColumnDataSource(data=dict(ageGroup=age_group_counts.index.tolist(), count=age_group_counts.values))

p3 = figure(x_range=age_group_counts.index.tolist(), height=300, title="Age Group Distribution",
            toolbar_location=None, tools="")
p3.vbar(x='ageGroup', top='count', width=0.9, source=age_source)
p3.y_range.start = 0

# --- 4. Average Hours Contributed per Program ---
hours_avg = df.groupby('programName')['hoursContribution'].mean().dropna().sort_values(ascending=False)
hours_source = ColumnDataSource(data=dict(program=hours_avg.index.tolist(), avgHours=hours_avg.values))

p4 = figure(x_range=hours_avg.index.tolist(), height=300, title="Average Hours Contributed per Program",
            toolbar_location=None, tools="")
p4.vbar(x='program', top='avgHours', width=0.9, source=hours_source)
p4.xaxis.major_label_orientation = pi/4
p4.y_range.start = 0

# --- 5. Total Membership Payments by Location ---
membership_payments = df.groupby('location')['membershipPayment'].sum().sort_values(ascending=False)
membership_source = ColumnDataSource(data=dict(location=membership_payments.index.tolist(), totalPayment=membership_payments.values))

p5 = figure(x_range=membership_payments.index.tolist(), height=300, title="Total Membership Payments by Location",
            toolbar_location=None, tools="")
p5.vbar(x='location', top='totalPayment', width=0.9, source=membership_source)
p5.xaxis.major_label_orientation = pi/4
p5.y_range.start = 0

# --- 6. Skill Distribution ---
skill_counts = df['skill'].value_counts()
skill_source = ColumnDataSource(data=dict(skill=skill_counts.index.tolist(), count=skill_counts.values))

p6 = figure(y_range=skill_counts.index.tolist(), height=300, title="Skill Distribution",
            toolbar_location=None, tools="")
p6.hbar(y='skill', right='count', height=0.7, source=skill_source)
p6.x_range.start = 0

# --- 7. Donation vs Membership Payment Scatter Plot ---
df['donation'] = pd.to_numeric(df['donation'], errors='coerce').fillna(0)
df['membershipPayment'] = pd.to_numeric(df['membershipPayment'], errors='coerce').fillna(0)

color_map = {'True': 'green', 'False': 'red'}
df['volunteerStatusStr'] = df['isVolunteer'].astype(str)

p7 = figure(height=300, width=400, title="Donation vs Membership Payment",
            x_axis_label="Membership Payment (pesos)", y_axis_label="Donation (pesos)",
            tools="pan,wheel_zoom,box_zoom,reset")

p7.circle('membershipPayment', 'donation', size=7,
          color=factor_cmap('volunteerStatusStr', palette=['red', 'green'], factors=['False', 'True']),
          legend_field='volunteerStatusStr', source=df)

p7.legend.title = 'Is Volunteer'
p7.legend.location = 'top_left'

# --- 8. Average Rating by User Role ---
df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
rating_by_role = df.groupby('userRole')['averageRating'].mean().dropna().sort_values(ascending=False)
rating_role_source = ColumnDataSource(data=dict(role=rating_by_role.index.tolist(), avgRating=rating_by_role.values))

p8 = figure(x_range=rating_by_role.index.tolist(), height=300, title="Average Rating by User Role",
            toolbar_location=None, tools="")
p8.vbar(x='role', top='avgRating', width=0.9, source=rating_role_source)
p8.xaxis.major_label_orientation = pi/4
p8.y_range.start = 0

# --- 9. Active Volunteers by Program ---
active_volunteers = df[(df['status'] == 'active') & (df['isVolunteer'] == True)]
active_vol_counts = active_volunteers['programName'].value_counts()
active_vol_source = ColumnDataSource(data=dict(program=active_vol_counts.index.tolist(), count=active_vol_counts.values))

p9 = figure(x_range=active_vol_counts.index.tolist(), height=300, title="Active Volunteers by Program",
            toolbar_location=None, tools="")
p9.vbar(x='program', top='count', width=0.9, source=active_vol_source)
p9.xaxis.major_label_orientation = pi/4
p9.y_range.start = 0

# --- 10. Monthly New Membership Trends ---
df_members = df[df['isMember'] == True]
df_members = df_members.dropna(subset=['dateJoined'])
df_members['monthYear'] = df_members['dateJoined'].dt.to_period('M').astype(str)

monthly_new_members = df_members.groupby('monthYear').size().sort_index()
monthly_source = ColumnDataSource(data=dict(month=monthly_new_members.index.tolist(), count=monthly_new_members.values))

p10 = figure(x_range=monthly_new_members.index.tolist(), height=300, width=900,
             title="Monthly New Membership Trends", toolbar_location=None, tools="")
p10.line(x='month', y='count', line_width=2, source=monthly_source)
p10.circle(x='month', y='count', size=5, source=monthly_source)
p10.xaxis.major_label_orientation = pi/4
p10.y_range.start = 0

# Layout all plots in a gridplot
dashboard = gridplot([
    [p1, p2],
    [p3, p4],
    [p5, p6],
    [p7, p8],
    [p9, p10]
], sizing_mode='scale_width')

show(dashboard)

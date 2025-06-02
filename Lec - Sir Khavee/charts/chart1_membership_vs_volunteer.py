from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
from bokeh.palettes import Category10
import numpy as np

def chart(df):
    df['membershipStatus'] = np.where(df['isMember'], 'Member', 'Not Member')
    df['volunteerStatus'] = np.where(df['isVolunteer'], 'Volunteer', 'Not Volunteer')

    membership_volunteer_counts = df.groupby(['membershipStatus', 'volunteerStatus']).size().reset_index(name='count')
    membership_volunteer_pivot = membership_volunteer_counts.pivot(index='membershipStatus', columns='volunteerStatus', values='count').fillna(0)
    membership_volunteer_pivot = membership_volunteer_pivot[['Volunteer', 'Not Volunteer']]  # order columns

    membership_statuses = membership_volunteer_pivot.index.tolist()
    volunteer_statuses = membership_volunteer_pivot.columns.tolist()

    data = {'membershipStatus': membership_statuses}
    for vs in volunteer_statuses:
        data[vs] = membership_volunteer_pivot[vs].values

    colors = Category10[10][:len(volunteer_statuses)]

    p = figure(x_range=membership_statuses, height=300, title="Membership Status vs Volunteer Status",
               toolbar_location=None, tools="")

    bottoms = np.zeros(len(membership_statuses))

    for i, vs in enumerate(volunteer_statuses):
        top = data[vs]
        cds = ColumnDataSource(data=dict(
            membershipStatus=membership_statuses,
            top=top,
            bottom=bottoms
        ))
        p.vbar(x='membershipStatus', top='top', bottom='bottom', width=0.9,
               color=colors[i], legend_label=vs, source=cds)
        bottoms += top

    p.y_range.start = 0
    p.xgrid.grid_line_color = None
    p.axis.minor_tick_line_color = None
    p.outline_line_color = None
    p.legend.location = "top_right"
    p.legend.orientation = "horizontal"

    return p

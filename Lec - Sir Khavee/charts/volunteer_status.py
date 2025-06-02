from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from math import pi

def volunteer_status(df):
    counts = df['isVolunteer'].value_counts()
    labels = counts.index.map({True: 'Volunteer', False: 'Not Volunteer'}).tolist()
    values = counts.values

    total = sum(values)
    angles = [v/total * 2*pi for v in values]

    start_angles = []
    end_angles = []
    cumulative_angle = 0
    for angle in angles:
        start_angles.append(cumulative_angle)
        cumulative_angle += angle
        end_angles.append(cumulative_angle)

    source = ColumnDataSource(data=dict(
        start_angle=start_angles,
        end_angle=end_angles,
        color=["#718dbf", "#e84d60"],
        label=labels,
        value=values
    ))

    fig = figure(height=500, title="Volunteer Status", toolbar_location=None,
                 tools="hover", tooltips="@label: @value", x_range=(-1, 1), y_range=(-1, 1))

    # Draw wedges (pie slices)
    fig.wedge(x=0, y=0, radius=0.8,
              start_angle='start_angle', end_angle='end_angle',
              color='color', legend_field='label', source=source)

    # Draw white circle on top to create donut hole
    fig.annulus(x=0, y=0, inner_radius=0, outer_radius=0.4, color='white')

    fig.axis.visible = False
    fig.grid.visible = False
    fig.legend.location = "top_right"
    fig.legend.label_text_font_size = "12pt"

    return fig

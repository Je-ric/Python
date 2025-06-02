from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from math import pi

def donation_by_role(df):
    grouped = df.groupby('userRole')['donation'].sum().sort_values(ascending=False)
    grouped = grouped[grouped.index != '']  # Remove empty roles

    source = ColumnDataSource(data=dict(
        role=grouped.index.tolist(),
        donation=grouped.values,
    ))

    fig = figure(x_range=grouped.index.tolist(), height=350, title="Donations by Role",
                 toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    # Draw line and circles
    fig.line(x='role', y='donation', source=source, line_width=2, color="navy", alpha=0.7)
    fig.circle(x='role', y='donation', source=source, size=8, color="red", alpha=0.8)

    # Rotate x-axis labels for readability
    fig.xaxis.major_label_orientation = pi / 4
    fig.y_range.start = 0

    # Add interactive hover tool
    hover = HoverTool(tooltips=[
        ("Role", "@role"),
        ("Donation", "@donation{$0,0.00}"),
    ], mode='vline')

    fig.add_tools(hover)

    return fig

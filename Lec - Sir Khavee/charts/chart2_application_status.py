from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from math import pi

def chart(df):
    # Count application statuses, replace NaNs with 'No Application'
    app_status_counts = df['volunteerApplicationStatus'].fillna('No Application').value_counts()

    source = ColumnDataSource(data=dict(
        status=app_status_counts.index.tolist(),
        count=app_status_counts.values
    ))

    p = figure(x_range=app_status_counts.index.tolist(), height=350,
               title="Volunteer Application Status Distribution (Scatter Plot)",
               toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    # Scatter plot: x = categorical status, y = counts
    p.circle(x='status', y='count', size=15, source=source, color="navy", alpha=0.7)

    # Rotate x-axis labels for better readability
    p.xaxis.major_label_orientation = pi / 4
    p.y_range.start = 0

    # Add interactive hover tool
    hover = HoverTool(tooltips=[
        ("Status", "@status"),
        ("Count", "@count"),
    ])
    p.add_tools(hover)

    return p

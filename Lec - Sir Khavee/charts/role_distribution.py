from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
from math import pi
import numpy as np

def role_distribution(df):
    counts = df[df['userRole'] != '']['userRole'].value_counts().sort_index()
    roles = counts.index.tolist()
    values = counts.values
    
    # Numeric x for the roles (needed for step plot)
    x = np.arange(len(roles))
    
    # Create step data by duplicating x and y points to simulate steps
    xs = []
    ys = []
    
    for i in range(len(x)):
        if i == 0:
            xs.append(x[i])
            ys.append(values[i])
        else:
            xs.append(x[i])
            ys.append(values[i-1])
            xs.append(x[i])
            ys.append(values[i])
    
    # Add last point to flatten step at the end
    xs.append(xs[-1] + 1)
    ys.append(ys[-1])
    
    # Create figure with categorical x-axis labels + one extra blank label for step end
    x_labels = roles + ['']
    p = figure(x_range=x_labels, height=300, title="User Roles (Step Chart)",
               toolbar_location=None, tools="")
    
    p.line(xs, ys, line_width=2)
    p.circle(x, values, size=6, color="navy", alpha=0.6)  # points on steps
    
    p.xaxis.major_label_orientation = pi / 4
    p.y_range.start = 0
    p.xaxis.axis_label = "User Role"
    p.yaxis.axis_label = "Count"
    
    return p

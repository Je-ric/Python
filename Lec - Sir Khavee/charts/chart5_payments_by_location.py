from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
import numpy as np

def chart(df):
    # Extract membershipPayment column values (dropping NaNs)
    payments = df['membershipPayment'].dropna()

    # Compute histogram bins and counts
    hist, edges = np.histogram(payments, bins='auto')

    source = ColumnDataSource(data=dict(
        left=edges[:-1],
        right=edges[1:],
        count=hist
    ))

    p = figure(height=300, title="Histogram of Membership Payments",
               toolbar_location=None, tools="")

    p.quad(bottom=0, top='count', left='left', right='right', source=source,
           fill_color="navy", line_color="white", alpha=0.7)

    p.y_range.start = 0
    p.xaxis.axis_label = "Membership Payment"
    p.yaxis.axis_label = "Frequency"

    return p

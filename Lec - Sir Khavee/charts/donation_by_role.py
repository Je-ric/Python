from bokeh.plotting import figure
from math import pi


def donation_by_role(df):
    grouped = df.groupby('userRole')['donation'].sum().sort_values(ascending=False)
    grouped = grouped[grouped.index != '']  # Remove empty roles

    fig = figure(x_range=grouped.index.tolist(), height=300, title="Donations by Role",
                 toolbar_location=None, tools="")
    fig.vbar(x=grouped.index.tolist(), top=grouped.values, width=0.9)
    fig.xaxis.major_label_orientation = pi / 4
    fig.y_range.start = 0
    return fig